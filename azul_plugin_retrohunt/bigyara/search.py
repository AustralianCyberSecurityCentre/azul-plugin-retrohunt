"""High-level search interface for querying across existing .bgi indexes."""

import binascii
import hashlib
import logging
import multiprocessing as mp
import os
import subprocess  # noqa: S404  # nosec: B404
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from functools import partial

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

logger = logging.getLogger("bigyara.search")
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
    ["query_hash", "index_path", "rule_name"],
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

    def checked_data_callback(path: str, config: dict[bytes, bytes]) -> bytes:
        data: bytes = None

        if data_callback:
            try:
                data = data_callback(path, config)
            except Exception as e:
                raise DataCallbackException("Exception in data callback") from e
        else:
            raise ValueError("Invalid data callback")
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
            rule_atoms,
            rule_search_plans,
            checked_progress_callback,
            query_hash=query_hash,
        )

    for rule_name in rule_atoms:
        if len(rule_matches[rule_name]) > 0:
            logger.info(f'Found {len(rule_matches[rule_name])} indexed file matches for "{rule_name}"')
        else:
            del rule_matches[rule_name]
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
def _run_bgparse_task(bgparse_exec, index, rule_name, search_string, query_hash):
    """Worker function executed in subprocess pool."""
    cmd = f"{bgparse_exec} {search_string}{index}"

    start = time.time()

    process = subprocess.run(  # noqa S602
        cmd,
        shell=True,
        capture_output=True,
    )

    duration = time.time() - start

    return (
        rule_name,
        index,
        search_string,
        process.returncode,
        process.stdout,
        process.stderr,
        duration,
    )


def _broad_phase_search(
    query_type: int,
    indices: list[str],
    rule_atoms: RuleAtoms,
    rule_search_plans: RuleSearchPlans,
    progress_callback: ProgressCallback,
    query_hash: str,
) -> tuple[RuleFileMatches, FileConfig]:

    bgparse_exec = executables["bgparse"]
    logger.info("Rule search plans broad phase: %s", rule_search_plans)
    # ------------------------------------------------------------
    # 1. Precompute hex atoms
    # ------------------------------------------------------------
    # hex_atoms = {rule: [binascii.b2a_hex(a).upper().decode() for a in atoms] for rule, atoms in rule_atoms.items()}

    # ------------------------------------------------------------
    # 2. Precompute search strings
    # ------------------------------------------------------------
    # if query_type == QueryTypeEnum.SURICATA:
    # search_strings = {rule: ["-s " + " -s ".join(hex_atoms[rule]) + " "] for rule in rule_atoms}
    # else:
    # search_strings = {rule: [f"-s{h} " for h in hex_atoms[rule]] for rule in rule_atoms}

    search_strings: dict[str, list[str]] = {}

    for rule_name, plan in rule_search_plans.items():
        search_strings[rule_name] = []

        for group in plan.groups:
            for atom in group:
                hex_atom = binascii.b2a_hex(atom).upper().decode()
                search_strings[rule_name].append(f"-s{hex_atom} ")

    # ------------------------------------------------------------
    # 3. Build flat task list
    # ------------------------------------------------------------
    tasks = []
    logger.info("Broad phase index file sizes:")
    total_io_bytes = 0
    for index in indices:
        size_bytes = os.path.getsize(index)
        atom_count = sum(len(atoms) for atoms in rule_atoms.values())
        total_io_bytes += size_bytes * atom_count
        for rule_name, s_list in search_strings.items():
            for s in s_list:
                # get_free_shm_bytes()
                tasks.append((index, rule_name, s))
    logger.info(f"Estimated total broad-phase I/O: {total_io_bytes / (1024 * 1024 * 1024):.2f} GB")
    search_count = len(tasks)
    searches_complete = 0

    progress_callback(SearchPhaseEnum.BROAD_PHASE, 0, search_count, None)

    # ------------------------------------------------------------
    # 4. Run tasks in multiprocessing pool (patched)
    # ------------------------------------------------------------
    worker = partial(_run_bgparse_task, bgparse_exec, query_hash=query_hash)

    rule_matches: RuleFileMatches = {rule: [] for rule in rule_atoms}
    file_config: FileConfig = {}

    with mp.Pool() as pool:
        # starmap is pickle‑safe and expands tuples automatically
        for (
            rule_name,
            index,
            search_string,
            returncode,
            stdout,
            stderr,
            duration,
        ) in pool.starmap(worker, tasks):
            prom_bgparse_duration.labels(
                query_hash=query_hash,
                index_path=index,
                rule_name=rule_name,
            ).observe(duration)
            # ------------------------------------------------------------
            # Error handling
            # ------------------------------------------------------------
            if returncode != 0:
                raise BiggrepException(
                    f"bgparse returned exit code {returncode}. Args: {search_string}{index}\n{stderr}"
                )

            if b"<error>" in stderr:
                error_message = stderr.decode().split("<error>", 1)[1].split(":", 1)[1].split("\n")[0]
                raise BiggrepException(
                    f"bgparse error:{error_message} - errored while searching for {rule_name} in {index}"
                )

            # ------------------------------------------------------------
            # 5. Aggregate results
            # ------------------------------------------------------------

            new_matches, file_config = _process_bgparse_output(
                stdout,
                rule_name,
                rule_matches[rule_name],
                file_config,
                query_hash=query_hash,
                index_path=index,
            )

            # DEBUG: inspect a few file configs
            logged_metadata = False
            if not logged_metadata and file_config:
                logged_metadata = True

                sample_cfg = next(iter(file_config.values()))

                logger.info(
                    "Indexed metadata keys: %s",
                    sorted(k.decode(errors="ignore") for k in sample_cfg),
                )

            rule_matches[rule_name].extend(new_matches)

            searches_complete += 1
            progress_callback(
                SearchPhaseEnum.BROAD_PHASE,
                searches_complete,
                search_count,
                (rule_name, new_matches),
            )

    if all(len(v) == 0 for v in rule_matches.values()):
        raise NoIndexMatchesException("Search aborted due to index matches.")

    logger.debug("All index searches completed")

    return (rule_matches, file_config)


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


def _narrow_phase_search(
    queryType: QueryTypeEnum,
    rule_matches: RuleFileMatches,
    rule_content: RuleContent,
    file_config: FileConfig,
    data_callback: DataCallback,
    progress_callback: ProgressCallback,
    query_hash: str,
) -> RuleFileMatches:
    """Narrow phase search using whichever tool is relevant to the search type."""
    if queryType == QueryTypeEnum.STRING:
        return rule_matches

    # Convert rule_matches to sets for fast removal
    rule_matches_sets: dict[str, set[str]] = {rule_name: set(paths) for rule_name, paths in rule_matches.items()}

    # Invert mapping: file → rules
    file_to_rules: dict[str, set[str]] = defaultdict(set)
    for rule_name, paths in rule_matches_sets.items():
        for p in paths:
            file_to_rules[p].add(rule_name)

    # Precompile YARA rules once
    compiled_yara_rules = {}
    if queryType == QueryTypeEnum.YARA:
        for rule_name, content in rule_content.items():
            if not content.startswith('import "pe"\n'):
                rule_content[rule_name] = 'import "pe"\n' + content
            compiled_yara_rules[rule_name] = yara.compile(source=rule_content[rule_name])

    # Precompute total jobs
    total_jobs = sum(len(paths) for paths in rule_matches_sets.values())
    jobs_complete = 0

    progress_callback(SearchPhaseEnum.NARROW_PHASE, 0, total_jobs, None)

    # ------------------------------------------------------------
    # Worker function (pure, no side effects)
    # ------------------------------------------------------------
    def worker(file_path: str, rules_for_file: frozenset[str], query_hash: str):
        cfg = file_config.get(file_path)
        with prom_narrow_io_duration.labels(query_hash=query_hash).time():
            data = data_callback(file_path, cfg)

        if data:
            prom_narrow_io_bytes.labels(query_hash=query_hash).inc(len(data))

        if not data:
            prom_missing_files.labels(query_hash=query_hash).inc()
            return ("missing", file_path, rules_for_file, None)

        results = []
        for rule_name in rules_for_file:
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

            results.append((rule_name, matched))

        return ("ok", file_path, rules_for_file, results)

    # ------------------------------------------------------------
    # Run workers in parallel
    # ------------------------------------------------------------
    futures = []
    with ThreadPoolExecutor() as executor:
        for file_path, rules_for_file in file_to_rules.items():
            futures.append(executor.submit(worker, file_path, frozenset(rules_for_file), query_hash=query_hash))

        # Process results in deterministic order
        for f in futures:
            status, file_path, rules_for_file, results = f.result()

            if status == "missing":
                for rule_name in rules_for_file:
                    total_jobs -= 1
                    rule_matches_sets[rule_name].discard(file_path)
                continue

            for rule_name, matched in results:
                jobs_complete += 1

                if matched:
                    progress_callback(
                        SearchPhaseEnum.NARROW_PHASE,
                        jobs_complete,
                        total_jobs,
                        (rule_name, [file_path]),
                    )
                else:
                    progress_callback(
                        SearchPhaseEnum.NARROW_PHASE,
                        jobs_complete,
                        total_jobs,
                        (rule_name, []),
                    )
                    rule_matches_sets[rule_name].discard(file_path)

    # Convert back to lists and remove empty rules
    final_matches: RuleFileMatches = {}
    for rule_name, paths in rule_matches_sets.items():
        if paths:
            final_matches[rule_name] = list(paths)

    if final_matches:
        logger.info(f"Found {len(final_matches)} confirmed matches for provided yara rules.")
    else:
        logger.info("No rules matched after Narrowing.")

    return final_matches


# def get_free_shm_bytes():
#    """Warm up."""
#    _ = os.statvfs("/dev/shm")  # noqa: S108


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
