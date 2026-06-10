"""High-level search interface for querying across existing .bgi indexes."""

import binascii
import hashlib
import logging
import multiprocessing as mp
import os
import subprocess  # noqa: S404  # nosec: B404
import time
from collections import defaultdict
from functools import partial

import yara
from prometheus_client import Histogram

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
from .yara_parse import parse_yara_rules

BGPARSE_TIMING = defaultdict(float)
BGPARSE_CALLS = defaultdict(int)

# FUTURE: multiprocessing has been removed from search functionality.
#         performance should be investigated and improved where necessary.
#         in particular, subprocesses called in for loops should be done asynchronously,
#         in batches according to available core count.

logger = logging.getLogger("bigyara.search")

_DURATION_BUCKETS = [0.5, 1, 5, 10, 30, 60, 120, 300, 600, 1200, 2400]

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

    rule_atoms, rule_content = _atom_parse(query, query_type, checked_progress_callback)
    logger.info("Starting Broad search")
    with prom_broad_phase_duration.labels(query_hash=query_hash).time():
        rule_matches, file_config = _broad_phase_search(query_type, indices, rule_atoms, checked_progress_callback)

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


def _atom_parse(query: str, query_type: int, progress_callback: ProgressCallback) -> tuple[RuleAtoms, RuleContent]:
    rule_atoms: RuleAtoms = {}
    rule_content: RuleContent = None

    if query_type == QueryTypeEnum.STRING:
        progress_callback(SearchPhaseEnum.ATOM_PARSE, 0, 1, None)
        if len(query) >= SEARCH_ATOM_SIZE_MIN:
            rule_atoms[query] = [query.encode()]
            progress_callback(SearchPhaseEnum.ATOM_PARSE, 1, 1, (query, rule_atoms[query]))
    elif query_type == QueryTypeEnum.YARA:
        rule_atoms, rule_content = parse_yara_rules(query, progress_callback)
    elif query_type == QueryTypeEnum.SURICATA:
        rule_atoms, rule_content = parse_suricata_rules(query, progress_callback)
    else:
        raise ValueError("Invalid query type")

    if len(rule_atoms) == 0:
        raise NoAtomException(
            f"No search atoms found from input - ensure that all atoms will be at least {SEARCH_ATOM_SIZE_MIN} bytes."
        )

    return rule_atoms, rule_content


# FUTURE: investigate whether there is an alternative to biggrep that allows
#         batched searches as an OR on those searches.
def _run_bgparse_task(bgparse_exec, index, rule_name, search_string):
    """Worker function executed in subprocess pool."""
    cmd = f"{bgparse_exec} {search_string}{index}"

    process = subprocess.run(  # noqa S602
        cmd,
        shell=True,
        capture_output=True,
    )

    return (
        rule_name,
        index,
        search_string,
        process.returncode,
        process.stdout,
        process.stderr,
    )


def _broad_phase_search(
    query_type: int,
    indices: list[str],
    rule_atoms: RuleAtoms,
    progress_callback: ProgressCallback,
) -> tuple[RuleFileMatches, FileConfig]:

    bgparse_exec = executables["bgparse"]

    # ------------------------------------------------------------
    # 1. Precompute hex atoms
    # ------------------------------------------------------------
    hex_atoms = {rule: [binascii.b2a_hex(a).upper().decode() for a in atoms] for rule, atoms in rule_atoms.items()}

    # ------------------------------------------------------------
    # 2. Precompute search strings
    # ------------------------------------------------------------
    if query_type == QueryTypeEnum.SURICATA:
        search_strings = {rule: ["-s " + " -s ".join(hex_atoms[rule]) + " "] for rule in rule_atoms}
    else:
        search_strings = {rule: [f"-s{h} " for h in hex_atoms[rule]] for rule in rule_atoms}

    # ------------------------------------------------------------
    # 3. Build flat task list
    # ------------------------------------------------------------
    tasks = []
    for index in indices:
        for rule_name, s_list in search_strings.items():
            for s in s_list:
                tasks.append((index, rule_name, s))

    search_count = len(tasks)
    searches_complete = 0

    progress_callback(SearchPhaseEnum.BROAD_PHASE, 0, search_count, None)

    # ------------------------------------------------------------
    # 4. Run tasks in multiprocessing pool (patched)
    # ------------------------------------------------------------
    worker = partial(_run_bgparse_task, bgparse_exec)

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
        ) in pool.starmap(worker, tasks):
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

    # Timing summary
    for rule, total_time in BGPARSE_TIMING.items():
        calls = BGPARSE_CALLS[rule]
        avg = total_time / calls if calls else 0
        logger.debug(f"[TIMING] rule={rule} calls={calls} total={total_time:.6f}s avg={avg:.6f}s")

    return (rule_matches, file_config)


def _process_bgparse_output(
    output: bytes, rule_name: str, file_matches: list[str], file_config: FileConfig
) -> tuple[list[str], FileConfig]:
    """Turn bgparse stdout into a list of matching files and their config."""
    start = time.perf_counter()
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
                        raise FileConfigReadException(f"Could not read file config from index for {path}")
                    key, value = key_value
                    cfg[key] = value
                file_config[path] = cfg

    elapsed = time.perf_counter() - start
    BGPARSE_TIMING[rule_name] += elapsed
    BGPARSE_CALLS[rule_name] += 1

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
) -> RuleFileMatches:
    """Narrow phase search using whichever tool is relevant to the search type."""
    if queryType == QueryTypeEnum.STRING:
        return rule_matches

    # Invert the rule matches so that we know what rules each file uses.
    # This way if a file can't be found we don't compile the rule.
    file_to_all_matches_dict = defaultdict(list)
    for rule_name, file_path_list in rule_matches.items():
        for file_path in file_path_list:
            file_to_all_matches_dict[file_path].append(rule_name)

    total_jobs = 0
    jobs_complete = 0
    compiled_yara_rules: dict[str, yara.Rules] = dict()
    for rule_file_paths in rule_matches.values():
        total_jobs += len(rule_file_paths)
    progress_callback(SearchPhaseEnum.NARROW_PHASE, jobs_complete, total_jobs, None)

    for file_path, yara_rules in file_to_all_matches_dict.items():
        # Load data
        data = data_callback(file_path, file_config[file_path])
        if not data:
            logger.warning(f"Unable to locate data for {file_path} - skipping")
            for rule_name in yara_rules:
                # Decrement total jobs as file couldn't be located.
                total_jobs -= 1
                rule_matches[rule_name].remove(file_path)
            continue

        # Compile and cache yara rules
        if queryType == QueryTypeEnum.YARA:
            for rule_name in yara_rules:
                if rule_name in compiled_yara_rules:
                    continue
                # FUTURE: parse the imports from the top of the rule content to apply to all rules,
                #         instead of just assuming it needs pe.
                # FUTURE: make sure yara is compiled with all standard modules so that import them works.
                rule_content[rule_name] = 'import "pe"\n' + rule_content[rule_name]
                compiled_rule: yara.Rules = yara.compile(source=rule_content[rule_name])
                compiled_yara_rules[rule_name] = compiled_rule

        for rule_name in yara_rules:
            matched: bool = False
            if queryType == QueryTypeEnum.YARA:
                # FUTURE: this should have a better timeout.
                # FUTURE: yara include directives should be turned off.
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
            jobs_complete += 1
            if matched:
                # even though a narrow phase search is unnecessary for string searches,
                # we still call the progress callback in case the user is trying to do
                # something important in it.
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

                rule_matches[rule_name].remove(file_path)

    # Clear all of the now empty rule_matches.
    for rule_name in list(rule_matches.keys()):
        if not rule_matches[rule_name]:
            del rule_matches[rule_name]

    if rule_matches:
        logger.info(f"Found {len(rule_matches)} confirmed matches for provided yara rules.")
    else:
        logger.info("No rules matched after Narrowing.")

    return rule_matches


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
