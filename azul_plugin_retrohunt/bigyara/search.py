"""High-level search interface for querying across existing .bgi indexes."""

import asyncio
import binascii
import ctypes
import gc
import hashlib
import inspect
import logging
import multiprocessing as mp
import os
import subprocess  # noqa: S404  # nosec: B404
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from itertools import product
from threading import Event

import yara
from prometheus_client import Counter, Histogram

from azul_plugin_retrohunt.retrohunt import CancelException

from . import (
    SEARCH_ATOM_SIZE_MIN,
    DataCallback,
    FileConfig,
    ProgressCallback,
    QueryTypeEnum,
    RuleAtoms,
    RuleContent,
    RuleFileMatches,
    SearchPhaseEnum,
)
from .env import executables
from .suricata_parse import parse_suricata_rules
from .yara_parse import RuleSearchPlans, parse_yara_rules

# FUTURE: multiprocessing has been removed from search functionality.
#         performance should be investigated and improved where necessary.
#         in particular, subprocesses called in for loops should be done asynchronously,
#         in batches according to available core count.

stop_event = Event()
_narrow_event_loop: asyncio.AbstractEventLoop | None = None

# Hybrid narrow-phase pipeline limits. Downloads are asynchronous, while YARA
# scans run in a small dedicated thread pool so retrieval can continue during
# CPU-bound matching without allowing unbounded downloaded data to accumulate.
NARROW_ASYNC_DOWNLOADS = 8
NARROW_YARA_SCAN_THREADS = 2
NARROW_DOWNLOADED_QUEUE_SIZE = 2

logger = logging.getLogger("bigyara.search")
_LIBC = ctypes.CDLL("libc.so.6")
_DURATION_BUCKETS = [0.01, 0.05, 0.1, 0.2, 0.3, 0.5, 1, 5, 10, 30, 60, 120, 300, 600, 1200, 2400]

prom_broad_phase_duration = Histogram(
    "retrohunt_broad_phase_duration_seconds",
    "Time spent in broad phase search.",
    ["query_hash"],
    buckets=_DURATION_BUCKETS,
)
prom_narrow_phase_duration = Histogram(
    "retrohunt_narrow_phase_duration_seconds",
    "Time spent in narrow phase search.",
    ["query_hash"],
    buckets=_DURATION_BUCKETS,
)
# bgparse latency
prom_bgparse_duration = Histogram(
    "retrohunt_bgparse_duration_seconds",
    "Time spent executing bgparse during broad phase.",
    ["query_hash"],
    buckets=_DURATION_BUCKETS,
)
# PVC/index potential issues
prom_bgparse_errors = Counter(
    "retrohunt_bgparse_errors_total",
    "Number of bgparse errors encountered during broad phase.",
    ["query_hash", "index_path", "rule_name"],
)
# per-file read latency
prom_narrow_io_duration = Histogram(
    "retrohunt_narrow_io_duration_seconds",
    "Time spent reading file data during narrow phase.",
    ["query_hash"],
    buckets=_DURATION_BUCKETS,
)
# Throughput
prom_narrow_io_bytes = Counter(
    "retrohunt_narrow_io_bytes_total",
    "Total bytes read during narrow phase.",
    ["query_hash"],
)
# stale index check
prom_missing_files = Counter(
    "retrohunt_missing_files_total",
    "Number of files missing during narrow phase.",
    ["query_hash"],
)
# CPU time spent matching
prom_narrow_cpu_duration = Histogram(
    "retrohunt_narrow_cpu_duration_seconds",
    "CPU time spent matching rules during narrow phase.",
    ["query_hash", "rule_name"],
    buckets=_DURATION_BUCKETS,
)


class BiggrepException(Exception):
    """Error when running bgparse."""

    pass


class NoAtomException(Exception):
    """No valid atoms found in query."""

    pass


class NoIndexMatchesException(Exception):
    """No file matches found in indices."""

    pass


class ProgressCallbackException(Exception):
    """An exception occurred in the user-supplied progress callback."""

    pass


class DataCallbackException(Exception):
    """An exception occurred in the user-supplied data callback."""

    pass


class FileConfigReadException(Exception):
    """Could not read file config stored in index."""

    pass


def search(
    query: str,
    query_type: QueryTypeEnum | int,
    index_dirs: str | list[str],
    data_callback: DataCallback = None,
    progress_callback: ProgressCallback = None,
    recursive: bool = True,
) -> RuleFileMatches:
    """Do a BigYara search.

    The search happen in 3 stages:
     - atomic strings are extracted from the query,
     - a broad phase search is done by searching for the atoms via biggrep,
     - a narrow phase search is done by by using the tool specific to the query type.
    """
    # ensure types are what we expect
    if not isinstance(query, str):
        raise TypeError("query must be str.")

    # YARA and Suricata searches require the original file data during the
    # narrow phase. Validate this before starting any multiprocessing or
    # thread-pool work so the caller receives a predictable ValueError.
    if query_type in {QueryTypeEnum.YARA, QueryTypeEnum.SURICATA} and data_callback is None:
        raise ValueError("A data callback is required for YARA and Suricata searches.")

    if not isinstance(index_dirs, list):
        index_dirs = [index_dirs]

    # get the list of index files we are working with
    indices: list[str] = _get_index_files(index_dirs, recursive)
    if not indices:
        raise FileNotFoundError(f"No .bgi indices found in {index_dirs}")

    # pass-through inner functions to check that callbacks exist and don't throw exceptions
    def checked_progress_callback(
        search_phase: int,
        jobs_done: int,
        total_jobs: int,
        completed_item: tuple[str, list[str | bytes]],
    ):
        if progress_callback:
            try:
                progress_callback(search_phase, jobs_done, total_jobs, completed_item)
            except CancelException:
                raise
            except Exception as e:
                raise ProgressCallbackException("Exception in progress callback") from e

    async def checked_data_callback(path: str, config: dict[bytes, bytes]) -> bytes | None:
        if not data_callback:
            raise ValueError("Invalid data callback")

        try:
            data = data_callback(path, config)
            if inspect.isawaitable(data):
                data = await data
        except CancelException:
            raise
        except Exception as e:
            raise DataCallbackException("Exception in data callback") from e

        return data

    if query_type == QueryTypeEnum.STRING:
        # string searches don't actually require the file data to succeed,
        # therefore the data callback is not used.
        if data_callback:
            logger.debug("Data callback is not used for string searches.")

    query_hash = hashlib.sha256(query.encode()).hexdigest()

    rule_atoms, rule_content, rule_search_plans = _atom_parse(query, query_type, checked_progress_callback)
    logger.info("Starting Broad search optimised")
    with prom_broad_phase_duration.labels(query_hash=query_hash).time():
        rule_matches, file_config = _broad_phase_search(
            query_type,
            indices,
            rule_search_plans,
            checked_progress_callback,
            query_hash=query_hash,
        )

    for rule_name in rule_atoms:
        matches = rule_matches.get(rule_name, [])

        if matches:
            logger.info(f'Found {len(matches)} indexed file matches for "{rule_name}"')
        else:
            rule_matches.pop(rule_name, None)
            logger.info(f'Did not find any indexed file matches for "{rule_name}"')
    logger.info("Starting narrow search ")
    with prom_narrow_phase_duration.labels(query_hash=query_hash).time():
        rule_matches = _narrow_phase_search(
            query_type,
            rule_matches,
            rule_content,
            file_config,
            checked_data_callback,
            checked_progress_callback,
            query_hash=query_hash,
        )

    return rule_matches


def _get_index_files(directories: list[str], recursive: bool) -> list[str]:
    """Return list of .bgi files found in directories."""
    # taking a copy so we can add subdirectories and remove directories as they are searched.
    search_dirs = directories.copy()

    index_files = []
    while len(search_dirs) > 0:
        dir_contents: list[str] = os.listdir(search_dirs[0])
        for dir_entry in dir_contents:
            dir_entry_path = os.path.join(search_dirs[0], dir_entry)
            if os.path.isfile(dir_entry_path):
                if not dir_entry.startswith(".") and dir_entry.endswith(".bgi"):
                    index_files.append(dir_entry_path)
            elif recursive and os.path.isdir(dir_entry_path):
                search_dirs.append(dir_entry_path)
        del search_dirs[0]
    logger.info(f"{len(index_files)} .bgi index files found")
    return index_files


def _atom_parse(
    query: str, query_type: int, progress_callback: ProgressCallback
) -> tuple[
    RuleAtoms,
    RuleContent,
    RuleSearchPlans,
]:
    rule_atoms: RuleAtoms = {}
    rule_content: RuleContent = None
    rule_search_plans: RuleSearchPlans = {}

    if query_type == QueryTypeEnum.STRING:
        progress_callback(SearchPhaseEnum.ATOM_PARSE, 0, 1, None)
        if len(query) >= SEARCH_ATOM_SIZE_MIN:
            rule_atoms[query] = [query.encode()]
            progress_callback(SearchPhaseEnum.ATOM_PARSE, 1, 1, (query, rule_atoms[query]))
    elif query_type == QueryTypeEnum.YARA:
        rule_atoms, rule_content, rule_search_plans = parse_yara_rules(query, progress_callback)
    elif query_type == QueryTypeEnum.SURICATA:
        rule_atoms, rule_content = parse_suricata_rules(query, progress_callback)
    else:
        raise ValueError("Invalid query type")

    if len(rule_atoms) == 0:
        raise NoAtomException(
            f"No search atoms found from input - ensure that all atoms will be at least {SEARCH_ATOM_SIZE_MIN} bytes."
        )

    return rule_atoms, rule_content, rule_search_plans


# FUTURE: investigate whether there is an alternative to biggrep that allows
#         batched searches as an OR on those searches.
def _run_bgparse_task(
    bgparse_exec,
    index,
    rule_name,
    group_idx,
    search_string,
):
    """Worker function executed in subprocess pool."""
    cmd = f"{bgparse_exec} {search_string}{index}"

    process = subprocess.run(  # noqa S602
        cmd,
        shell=True,
        capture_output=True,
    )

    return (
        rule_name,
        group_idx,
        index,
        search_string,
        process.returncode,
        process.stdout,
        process.stderr,
    )


def _broad_phase_search(
    query_type: int,
    indices: list[str],
    rule_search_plans: RuleSearchPlans,
    progress_callback: ProgressCallback,
    query_hash: str,
) -> tuple[RuleFileMatches, FileConfig]:

    if query_type == QueryTypeEnum.SURICATA:
        # not supporting Suricata yet
        return

    bgparse_exec = executables["bgparse"]
    logger.info("Rule search plans broad phase: %s", rule_search_plans)

    search_strings: dict[str, list[tuple[int, str]]] = {}
    broad_phase_modes: dict[str, str] = {}

    for rule_name, plan in rule_search_plans.items():
        search_strings[rule_name] = []

        required_string_group_options: list[list[int]] = []
        required_strings_usable = bool(getattr(plan, "required_strings", None))

        if required_strings_usable:
            for string_name in sorted(plan.required_strings):
                valid_group_ids = [
                    group_idx
                    for group_idx in plan.string_groups.get(string_name, [])
                    if 0 <= group_idx < len(plan.groups)
                ]

                if not valid_group_ids:
                    required_strings_usable = False
                    logger.warning(
                        'Rule "%s": required string %s has no usable atom groups',
                        rule_name,
                        string_name,
                    )
                    break

                required_string_group_options.append(valid_group_ids)

        if required_strings_usable and required_string_group_options:
            broad_phase_modes[rule_name] = "required_strings"

            for combination_index, group_combination in enumerate(product(*required_string_group_options)):
                combined_atoms: list[bytes] = []

                for group_idx in group_combination:
                    combined_atoms.extend(plan.groups[group_idx])

                unique_atoms = list(dict.fromkeys(combined_atoms))
                hex_atoms = [binascii.b2a_hex(atom).upper().decode() for atom in unique_atoms]

                search_id = -(combination_index + 1)
                search_strings[rule_name].append(
                    (
                        search_id,
                        "".join(f"-s{hex_atom} " for hex_atom in hex_atoms),
                    )
                )
            logger.info(
                'Rule "%s": required_strings present; generated %d combined AND bgparse searches covering %d required strings',
                rule_name,
                len(search_strings[rule_name]),
                len(plan.required_strings),
            )

        else:
            required_group_ids: set[int] = set()

            if getattr(plan, "required_groups", None):
                for required_group in plan.required_groups:
                    for group_idx, actual_group in enumerate(plan.groups):
                        if set(actual_group) == set(required_group):
                            required_group_ids.add(group_idx)
                            break

            required_group_ids = {group_idx for group_idx in required_group_ids if 0 <= group_idx < len(plan.groups)}

            if required_group_ids:
                broad_phase_modes[rule_name] = "required_groups"

                for group_idx in sorted(required_group_ids):
                    group = plan.groups[group_idx]
                    hex_atoms = [binascii.b2a_hex(atom).upper().decode() for atom in group]
                    search_strings[rule_name].append(
                        (
                            group_idx,
                            "".join(f"-s{hex_atom} " for hex_atom in hex_atoms),
                        )
                    )
                logger.info(
                    'Rule "%s": no usable required_strings; generated %d required_group searches',
                    rule_name,
                    len(search_strings[rule_name]),
                )

            else:
                broad_phase_modes[rule_name] = "fallback"

                for group_idx, group in enumerate(plan.groups):
                    hex_atoms = [binascii.b2a_hex(atom).upper().decode() for atom in group]
                    search_strings[rule_name].append(
                        (
                            group_idx,
                            "".join(f"-s{hex_atom} " for hex_atom in hex_atoms),
                        )
                    )

                logger.info(
                    'Rule "%s": no required_strings/groups; generated %d fallback OR searches',
                    rule_name,
                    len(search_strings[rule_name]),
                )

    tasks = []
    for index in indices:
        for rule_name, grouped_searches in search_strings.items():
            for search_id, search_string in grouped_searches:
                tasks.append((index, rule_name, search_id, search_string))

    logger.info("Broad phase generated %d tasks", len(tasks))
    search_count = len(tasks)
    searches_complete = 0
    progress_callback(SearchPhaseEnum.BROAD_PHASE, 0, search_count, None)

    worker = partial(_run_bgparse_task, bgparse_exec)
    file_config: FileConfig = {}
    search_matches: dict[str, dict[int, set[str]]] = {
        rule_name: {search_id: set() for search_id, _ in grouped_searches}
        for rule_name, grouped_searches in search_strings.items()
    }

    start = time.time()

    pool = mp.Pool()
    try:
        result_iterator = pool.starmap_async(worker, tasks)

        while not result_iterator.ready():
            # This callback checks Redis for an externally requested cancellation.
            progress_callback(
                SearchPhaseEnum.BROAD_PHASE,
                searches_complete,
                search_count,
                None,
            )
            time.sleep(0.5)

        results = result_iterator.get()

        for (
            rule_name,
            search_id,
            index,
            search_string,
            returncode,
            stdout,
            stderr,
        ) in results:
            if returncode != 0:
                raise BiggrepException(
                    f"bgparse returned exit code {returncode}. Args: {search_string}{index}\n{stderr}"
                )

            if b"<error>" in stderr:
                error_message = stderr.decode().split("<error>", 1)[1].split(":", 1)[1].split("\n")[0]
                raise BiggrepException(
                    f"bgparse error:{error_message} - errored while searching for {rule_name} in {index}"
                )

            new_matches, file_config = _process_bgparse_output(
                stdout,
                rule_name,
                [],
                file_config,
                query_hash=query_hash,
                index_path=index,
            )

            search_matches[rule_name][search_id].update(new_matches)
            searches_complete += 1
            progress_callback(
                SearchPhaseEnum.BROAD_PHASE,
                searches_complete,
                search_count,
                (rule_name, new_matches),
            )

        duration = time.time() - start

        prom_bgparse_duration.labels(
            query_hash=query_hash,
        ).observe(duration)

        logger.info(f"Total BigGrep parse time: {duration}")
        pool.close()
        pool.join()
    except CancelException:
        pool.terminate()
        raise
    except Exception:
        pool.terminate()
        raise
    finally:
        pool.join()

    logger.debug("All index searches completed")
    rule_matches: RuleFileMatches = {}

    for rule_name, _plan in rule_search_plans.items():
        mode = broad_phase_modes[rule_name]
        result_sets = list(search_matches[rule_name].values())
        final_matches = set.union(*result_sets) if result_sets else set()

        if mode == "required_strings":
            logger.info(
                'Rule "%s": %d combined required-string searches produced %d candidates',
                rule_name,
                len(result_sets),
                len(final_matches),
            )
        elif mode == "required_groups":
            logger.info(
                'Rule "%s": required_groups OR broad phase produced %d candidates',
                rule_name,
                len(final_matches),
            )
        else:
            logger.info(
                'Rule "%s": fallback OR over all groups produced %d candidates',
                rule_name,
                len(final_matches),
            )

        rule_matches[rule_name] = list(final_matches)

    if all(len(matches) == 0 for matches in rule_matches.values()):
        raise NoIndexMatchesException("Search aborted due to no index matches.")

    return rule_matches, file_config


def _process_bgparse_output(
    output: bytes,
    rule_name: str,
    file_matches: list[str],
    file_config: FileConfig,
    query_hash: str,
    index_path: str,
) -> tuple[list[str], FileConfig]:
    """Turn bgparse stdout into a list of matching files and their config."""
    new_match_paths = []

    if output:
        for line in output.splitlines():
            line = line.rstrip()
            if not line:
                continue

            parts = line.split(b",")
            path = parts[0].decode()

            if path not in file_matches:
                new_match_paths.append(path)

            if path not in file_config:
                cfg = {}
                for kv in parts[1:-1]:
                    key_value = kv.split(b"=", 1)
                    if len(key_value) != 2:
                        prom_bgparse_errors.labels(
                            query_hash=query_hash,
                            index_path=index_path,
                            rule_name=rule_name,
                        ).inc()
                        raise FileConfigReadException(f"Could not read file config from index for {path}")
                    key, value = key_value
                    cfg[key] = value
                file_config[path] = cfg

    return new_match_paths, file_config


def yara_callback(_data):
    """Yara callback to abort a yara search once a match is found."""
    return yara.CALLBACK_ABORT


def _get_narrow_event_loop() -> asyncio.AbstractEventLoop:
    """Return the worker process's persistent narrow-phase event loop."""
    global _narrow_event_loop

    if _narrow_event_loop is None or _narrow_event_loop.is_closed():
        _narrow_event_loop = asyncio.new_event_loop()

    return _narrow_event_loop


def _narrow_phase_search(
    queryType: QueryTypeEnum,
    rule_matches: RuleFileMatches,
    rule_content: RuleContent,
    file_config: FileConfig,
    data_callback: DataCallback,
    progress_callback: ProgressCallback,
    query_hash: str,
) -> RuleFileMatches:
    """Run the asynchronous narrow phase from the synchronous search API."""
    if queryType == QueryTypeEnum.STRING:
        return rule_matches

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        loop = _get_narrow_event_loop()
        return loop.run_until_complete(
            _narrow_phase_search_async(
                queryType,
                rule_matches,
                rule_content,
                file_config,
                data_callback,
                progress_callback,
                query_hash,
            )
        )

    raise RuntimeError("search() cannot start its narrow-phase event loop while another event loop is running.")


async def _narrow_phase_search_async(
    queryType: QueryTypeEnum,
    rule_matches: RuleFileMatches,
    rule_content: RuleContent,
    file_config: FileConfig,
    data_callback: DataCallback,
    progress_callback: ProgressCallback,
    query_hash: str,
) -> RuleFileMatches:
    """Narrow files with async downloads and bounded threaded matching."""
    # Convert rule_matches to sets for fast removal.
    rule_matches_sets: dict[str, set[str]] = {rule_name: set(paths) for rule_name, paths in rule_matches.items()}

    # Invert mapping: file -> rules. Each binary is downloaded only once even
    # when several rules selected it during the broad phase.
    file_to_rules: dict[str, set[str]] = defaultdict(set)
    for rule_name, paths in rule_matches_sets.items():
        for path in paths:
            file_to_rules[path].add(rule_name)

    # Precompile YARA rules once and share them with the two scan threads, as
    # the previous threaded implementation already did.
    compiled_yara_rules = {}
    if queryType == QueryTypeEnum.YARA:
        for rule_name, content in list(rule_content.items()):
            if not content.startswith('import "pe"\n'):
                content = 'import "pe"\n' + content
            compiled_yara_rules[rule_name] = yara.compile(source=content)

    def scan_file(
        file_path: str,
        rules_for_file: frozenset[str],
        data: bytes,
    ) -> list[tuple[str, bool]]:
        """Run all relevant tool scans for one downloaded file."""
        results: list[tuple[str, bool]] = []

        for rule_name in rules_for_file:
            if stop_event.is_set():
                raise CancelException("Narrow phase cancelled by user.")

            if queryType == QueryTypeEnum.YARA:
                with prom_narrow_cpu_duration.labels(
                    query_hash=query_hash,
                    rule_name=rule_name,
                ).time():
                    matched = (
                        len(
                            compiled_yara_rules[rule_name].match(
                                data=data,
                                callback=yara_callback,
                                which_callbacks=yara.CALLBACK_MATCHES,
                                fast=True,
                                timeout=60,
                            )
                        )
                        > 0
                    )
            elif queryType == QueryTypeEnum.SURICATA:
                matched = _run_suricata(rule_content[rule_name], file_path, data)
            else:
                raise ValueError("Invalid query type for narrow phase")

            results.append((rule_name, matched))

        return results

    # Precompute progress totals.
    total_jobs = sum(len(paths) for paths in rule_matches_sets.values())
    jobs_complete = 0

    total_files = len(file_to_rules)
    files_complete = 0
    next_progress_percent = 5

    progress_callback(SearchPhaseEnum.NARROW_PHASE, 0, total_jobs, None)

    logger.info(
        "Narrow search starting: %d unique files to process across %d rule/file jobs",
        total_files,
        total_jobs,
    )
    logger.info(
        "Initiating hybrid narrow search with %d async downloads, %d YARA scan threads and a %d-file downloaded queue",
        NARROW_ASYNC_DOWNLOADS,
        NARROW_YARA_SCAN_THREADS,
        NARROW_DOWNLOADED_QUEUE_SIZE,
    )

    # The queue contains only complete downloads waiting for a scan thread.
    # Its small maxsize provides backpressure when matching is slower than I/O.
    downloaded_queue: asyncio.Queue[tuple[str, frozenset[str], bytes | None] | None] = asyncio.Queue(
        maxsize=NARROW_DOWNLOADED_QUEUE_SIZE
    )

    # A shared iterator avoids creating one task per candidate on 100k+ hunts.
    # Calls to next() happen without an await, so access is serialized by the
    # event loop and no additional lock is needed.
    task_iterator = iter(file_to_rules.items())

    async def download_worker(worker_number: int):
        """Fetch files asynchronously and enqueue complete binary buffers."""
        while True:
            if stop_event.is_set():
                raise CancelException("Narrow phase cancelled by user.")

            try:
                file_path, rules_for_file = next(task_iterator)
            except StopIteration:
                return

            frozen_rules = frozenset(rules_for_file)
            cfg = file_config.get(file_path)

            with prom_narrow_io_duration.labels(query_hash=query_hash).time():
                data = await data_callback(file_path, cfg)

            # Cancellation may have been requested while the dispatcher stream
            # was active.
            if stop_event.is_set():
                raise CancelException("Narrow phase cancelled by user.")

            if data:
                prom_narrow_io_bytes.labels(query_hash=query_hash).inc(len(data))
            else:
                prom_missing_files.labels(query_hash=query_hash).inc()

            # This await applies backpressure when both scan threads and the
            # bounded queue are occupied. Each downloader retains at most its
            # current file while waiting.
            await downloaded_queue.put((file_path, frozen_rules, data))
            logger.debug(
                "Async download worker %d queued %s",
                worker_number,
                file_path,
            )

    def record_file_complete(
        file_path: str,
        rules_for_file: frozenset[str],
        results: list[tuple[str, bool]] | None,
    ):
        """Apply one scanned or missing-file result on the event-loop thread."""
        nonlocal files_complete, jobs_complete, next_progress_percent, total_jobs

        files_complete += 1
        current_percent = (files_complete * 100) // total_files if total_files else 100

        while current_percent >= next_progress_percent:
            logged_percent = next_progress_percent
            logger.info(
                "Narrow search %d%% complete: %d/%d files processed",
                logged_percent,
                files_complete,
                total_files,
            )
            next_progress_percent += 5

            rss_before_mib = _read_process_rss_mib()

            gc.collect()
            _LIBC.malloc_trim(0)

            rss_after_mib = _read_process_rss_mib()

            logger.info(
                "Narrow memory trim at %d%%: RSS before=%d MiB, RSS after=%d MiB",
                logged_percent,
                rss_before_mib,
                rss_after_mib,
            )

        if results is None:
            for rule_name in rules_for_file:
                total_jobs -= 1
                rule_matches_sets[rule_name].discard(file_path)
            return

        for rule_name, matched in results:
            jobs_complete += 1

            completed_item = (
                rule_name,
                [file_path] if matched else [],
            )

            progress_callback(
                SearchPhaseEnum.NARROW_PHASE,
                jobs_complete,
                total_jobs,
                completed_item,
            )

            if not matched:
                rule_matches_sets[rule_name].discard(file_path)

    loop = asyncio.get_running_loop()
    scan_executor = ThreadPoolExecutor(
        max_workers=NARROW_YARA_SCAN_THREADS,
        thread_name_prefix="retrohunt-yara",
    )

    async def scan_worker(worker_number: int):
        """Drain downloaded files and run matching in the scan thread pool."""
        while True:
            item = await downloaded_queue.get()
            try:
                if item is None:
                    return

                file_path, rules_for_file, data = item

                if stop_event.is_set():
                    raise CancelException("Narrow phase cancelled by user.")

                if not data:
                    record_file_complete(file_path, rules_for_file, None)
                    continue

                results = await loop.run_in_executor(
                    scan_executor,
                    scan_file,
                    file_path,
                    rules_for_file,
                    data,
                )

                # Release the complete binary before callbacks and the next
                # queue read. This keeps the number of retained buffers bounded.
                data = None

                if stop_event.is_set():
                    raise CancelException("Narrow phase cancelled by user.")

                record_file_complete(file_path, rules_for_file, results)
                logger.debug(
                    "YARA scan worker %d processed %s",
                    worker_number,
                    file_path,
                )
            finally:
                # Drop the queue item's reference to the downloaded binary even
                # when matching or a callback raises.
                item = None
                downloaded_queue.task_done()

    download_tasks = [
        asyncio.create_task(
            download_worker(worker_number),
            name=f"narrow-download-{worker_number}",
        )
        for worker_number in range(NARROW_ASYNC_DOWNLOADS)
    ]
    scan_tasks = [
        asyncio.create_task(
            scan_worker(worker_number),
            name=f"narrow-scan-{worker_number}",
        )
        for worker_number in range(NARROW_YARA_SCAN_THREADS)
    ]

    async def finish_downloads_and_stop_scanners():
        """Wait for all fetchers, then terminate scanners after queue drain."""
        await asyncio.gather(*download_tasks)
        for _ in scan_tasks:
            await downloaded_queue.put(None)

    coordinator_task = asyncio.create_task(
        finish_downloads_and_stop_scanners(),
        name="narrow-download-coordinator",
    )

    all_tasks = [coordinator_task, *download_tasks, *scan_tasks]
    try:
        # Scanner exceptions propagate immediately. The coordinator prevents
        # sentinel insertion until every downloader has finished.
        await asyncio.gather(coordinator_task, *scan_tasks)
    except BaseException:
        stop_event.set()
        for task in all_tasks:
            task.cancel()
        await asyncio.gather(*all_tasks, return_exceptions=True)
        raise
    finally:
        # Running YARA calls cannot be force-killed safely, matching the old
        # ThreadPool behaviour. Pending scans are cancelled and active scans
        # are allowed to finish before their binary buffers are released.
        scan_executor.shutdown(wait=True, cancel_futures=True)

    # Convert back to lists and remove empty rules.
    final_matches: RuleFileMatches = {}
    for rule_name, paths in rule_matches_sets.items():
        if paths:
            final_matches[rule_name] = list(paths)

    if final_matches:
        confirmed_file_matches = sum(len(paths) for paths in final_matches.values())
        logger.info(
            "Found %d confirmed file matches across %d YARA rules.",
            confirmed_file_matches,
            len(final_matches),
        )
    else:
        logger.info("No rules matched after Narrowing.")

    return final_matches


def trigger_stop_event():
    """Set the shared stop event if the user cancels manually."""
    stop_event.set()


def clear_stop_event():
    """Clear the stop event flag."""
    stop_event.clear()


def calculate_narrow_search_concurrency() -> int:
    """Calculate safe in-flight async narrow-phase work from the container limit."""
    _MIB_PER_GIB = 512

    # The async implementation still buffers one complete binary per in-flight
    # worker before YARA scans it, so retain the measured per-worker memory model
    # used by the threaded implementation for an apples-to-apples comparison.
    _NARROW_BASELINE_MEMORY_MIB = 10 * _MIB_PER_GIB
    _NARROW_MEMORY_PER_ASYNC_WORKER_MIB = 1 * _MIB_PER_GIB
    _NARROW_MEMORY_RESERVE_MIB = 2 * _MIB_PER_GIB
    _NARROW_ABSOLUTE_ASYNC_WORKER_CAP = 10

    raw_memory_limit = os.getenv("CONTAINER_MEMORY_LIMIT_MI")

    if raw_memory_limit is None:
        logger.warning("CONTAINER_MEMORY_LIMIT_MI is not set; defaulting narrow search to 1 async worker.")
        return 1

    try:
        memory_limit_mib = int(raw_memory_limit)
    except ValueError:
        logger.warning(
            "Invalid CONTAINER_MEMORY_LIMIT_MI=%r; defaulting narrow search to 1 async worker.",
            raw_memory_limit,
        )
        return 1

    memory_available_for_workers_mib = memory_limit_mib - _NARROW_BASELINE_MEMORY_MIB - _NARROW_MEMORY_RESERVE_MIB

    if memory_available_for_workers_mib < _NARROW_MEMORY_PER_ASYNC_WORKER_MIB:
        logger.warning(
            "Container memory limit of %d MiB is below the measured safe "
            "narrow-search requirement. Defaulting to 1 async worker. "
            "Estimated baseline=%d MiB, reserve=%d MiB.",
            memory_limit_mib,
            _NARROW_BASELINE_MEMORY_MIB,
            _NARROW_MEMORY_RESERVE_MIB,
        )
        return 1

    memory_allowed_workers = memory_available_for_workers_mib // _NARROW_MEMORY_PER_ASYNC_WORKER_MIB

    workers = max(
        1,
        min(memory_allowed_workers, _NARROW_ABSOLUTE_ASYNC_WORKER_CAP),
    )

    logger.info(
        "Calculated narrow search async workers: %d "
        "(container limit=%d MiB, baseline=%d MiB, "
        "reserve=%d MiB, per-worker=%d MiB)",
        workers,
        memory_limit_mib,
        _NARROW_BASELINE_MEMORY_MIB,
        _NARROW_MEMORY_RESERVE_MIB,
        _NARROW_MEMORY_PER_ASYNC_WORKER_MIB,
    )

    return workers


def calculate_narrow_search_threads() -> int:
    """Backward-compatible alias for existing tests and callers."""
    return calculate_narrow_search_concurrency()


def _read_process_rss_mib() -> int:
    try:
        with open("/proc/self/status", encoding="utf-8") as status_file:
            for line in status_file:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError):
        logger.exception("Unable to read process RSS")

    return 0


def _run_suricata(rule_text: str, file_path: str, data: bytes) -> bool:
    """Run suricata rule on data. Returns True if there is at least one match."""
    # FUTURE suricata - implement
    raise NotImplementedError("Suricata is not implemented yet.")
    # matched = False
    # try:
    #     # create a temp dir with the conf required to run
    #     with tempfile.TemporaryDirectory(prefix="snort_") as tmp_dir:
    #         with open(os.path.join(tmp_dir, "snort.conf"), "w") as conf_file:
    #             baseconf = open(os.path.join(os.path.dirname(__file__), "snort_config/snort_base.conf"), "r").read()
    #             conf_file.write(f"{baseconf}\n{rule_text}\n")
    #         shutil.copy(
    #             os.path.join(os.path.dirname(__file__), "snort_config/snort_classification.config"),
    #             os.path.join(tmp_dir, "classification.config"),
    #         )

    #         # if we are retrieving a copy of the file, write to the tmp location too
    #         tmp_data_path = os.path.join(tmp_dir, "sample.pcap")
    #         with open(tmp_data_path, "wb") as data_file:
    #             data_file.write(data)

    #         # run snort using the above conf/sample
    #         # FUTURE: all this snort library does is call the snort process and parse the output.
    #         #         since we only care whether it returned at least one result,
    #         #         can we just call snort directly and not have to go through the library?
    #         #         this would give the added bonus of being able to pass a timeout to the process.
    #         snort_searcher = Snort(
    #         {"path": "snort", "config": os.path.join(tmp_dir, "snort.conf"), "extra_args": ""})
    #         matched = len(snort_searcher.run(tmp_data_path)[1]) > 0
    # except Exception as e:
    #     logger.warning(f"Snort failed to run on {file_path}: {e}")
    # return matched
