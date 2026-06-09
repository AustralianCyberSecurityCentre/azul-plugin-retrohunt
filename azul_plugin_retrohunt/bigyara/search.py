"""High-level search interface for querying across existing .bgi indexes."""

import binascii
import hashlib
import logging
import os
import subprocess  # noqa: S404  # nosec: B404
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

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

# tune these
RULE_BATCH_SIZE = 20  # how many rules per bgparse call
INDEX_BATCH_SIZE = 10  # how many indices per bgparse call
MAX_WORKERS = 8  # parallel bgparse calls
_rule_atom_cache = {}
_batch_cmd_cache = {}

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

    raw_rule_atoms, rule_content = _atom_parse(query, query_type, checked_progress_callback)

    rule_atoms = {}

    for rule_name, atoms in raw_rule_atoms.items():
        before = len(atoms)
        # 1. Cache hit?
        if rule_name in _rule_atom_cache:
            rule_atoms[rule_name] = _rule_atom_cache[rule_name]
            continue

        # 2. Minimise atom explosion (nocase → fewer atoms)
        minimised = minimise_case_atoms(atoms)

        # 3. Store in cache
        _rule_atom_cache[rule_name] = minimised

        after = len(minimised)

        logger.info(f"[atoms] {rule_name}: {before} → {after} atoms")

        # 4. Use minimised atoms
        rule_atoms[rule_name] = minimised

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
def minimise_case_atoms(atoms):
    """Reduce atom explosion caused by nocase by collapsing case variants.

    If an atom differs only by ASCII case, keep only the lowercase version.
    """
    normalised = set()
    for atom in atoms:
        try:
            # Only normalise ASCII letters; leave binary atoms untouched
            lowered = bytes([b | 0x20 if 65 <= b <= 90 else b for b in atom])
            normalised.add(lowered)
        except Exception:
            normalised.add(atom)
    return list(normalised)


def batch_rules_by_atom_count(rule_items, max_atoms=250):
    """Group rules into batches such that the total atom count per batch.

    does not exceed max_atoms. This keeps bgparse calls balanced.
    """
    batch = []
    atom_total = 0

    for rule_name, atoms in rule_items:
        # If adding this rule would exceed the limit, yield the batch
        if batch and atom_total + len(atoms) > max_atoms:
            yield batch
            batch = []
            atom_total = 0

        batch.append((rule_name, atoms))
        atom_total += len(atoms)

    if batch:
        yield batch


def _chunked(seq, size):
    """Yield successive fixed‑size chunks from a sequence.

    Args:
        seq (Sequence): The sequence to split into chunks.
        size (int): Maximum size of each chunk.

    Yields:
        list: A slice of `seq` containing up to `size` elements.

    Notes:
        Used to batch rules or indices so the system can process them
        in manageable units rather than all at once.
    """
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def _run_bgparse_for_batch(
    query_type: int,
    index_batch: list[str],
    rule_batch: list[tuple[str, list[bytes]]],
) -> tuple[dict[str, list[str]], FileConfig]:
    """Run bgparse once for a batch of rules against a single index file.

    This function:
      - Builds (or reuses) a cached bgparse command prefix for the rule batch
      - Appends the index file to the command
      - Executes bgparse
      - Splits the output back into per‑rule match lists
      - Returns (rule_matches, file_config)
    """
    # bgparse only supports one index per invocation
    index = index_batch[0]

    # Cache key: sorted rule names (order does not matter)
    batch_key = tuple(sorted(rn for rn, _ in rule_batch))

    # 1. Check cache for command prefix
    if batch_key in _batch_cmd_cache:
        logger.debug(f"[cache] HIT for batch {batch_key}")
        cmd = _batch_cmd_cache[batch_key].copy()
    else:
        # 2. Build command prefix (expensive step)
        logger.debug(f"[cache] MISS for batch {batch_key} — building command")
        cmd = [executables["bgparse"]]
        for _, atoms in rule_batch:
            for atom in atoms:
                cmd.extend(["-s", binascii.b2a_hex(atom).upper().decode()])

        # 3. Store prefix in cache
        _batch_cmd_cache[batch_key] = cmd.copy()

    # 4. Append the index file (cannot be cached)
    cmd = cmd.copy()
    cmd.append(index)

    start = time.time()
    # Execute bgparse
    process = subprocess.run(  # noqa: S603
        cmd,
        capture_output=True,
    )

    duration = time.time() - start
    logger.info(f"[bgparse] {index} finished in {duration:.3f}s")

    if process.returncode != 0:
        raise BiggrepException(f"bgparse returned exit code {process.returncode}. Args: {cmd}\n{process.stderr}")

    if b"<error>" in process.stderr:
        error_message = process.stderr.decode().split("<error>", 1)[1].split(":", 1)[1].split("\n")[0]
        raise BiggrepException(f"bgparse error:{error_message} - errored while searching for {rule_batch} in {index}")

    # Prepare output containers
    batch_rule_matches: RuleFileMatches = {}
    batch_file_config: FileConfig = {}

    stdout = process.stdout

    # Parse output per rule
    for rule_name, _atoms in rule_batch:
        new_matches, batch_file_config = _process_bgparse_output(
            stdout,
            rule_name,
            batch_rule_matches.get(rule_name, []),
            batch_file_config,
        )
        batch_rule_matches.setdefault(rule_name, []).extend(new_matches)

    return batch_rule_matches, batch_file_config


def _broad_phase_search(
    query_type: int,
    indices: list[str],
    rule_atoms: RuleAtoms,
    progress_callback: ProgressCallback,
) -> tuple[RuleFileMatches, FileConfig]:
    """Optimized broad‑phase search that preserves correct semantics.

    - YARA: ANY atom may match → search atom‑by‑atom.
    - SURICATA: ALL atoms must match → batch atoms together.

    Parallelized across indices and atoms/rules.
    """
    rule_matches: RuleFileMatches = {}
    file_config: FileConfig = {}

    # Count total bgparse jobs
    if query_type == QueryTypeEnum.SURICATA:
        total_jobs = len(indices) * len(rule_atoms)
    else:
        total_jobs = sum(len(atoms) for atoms in rule_atoms.values()) * len(indices)

    searches_complete = 0
    progress_callback(SearchPhaseEnum.BROAD_PHASE, 0, total_jobs, None)

    lock = Lock()

    def run_single_bgparse(index: str, rule_name: str, search_args: list[str]):
        """Run bgparse for a single atom (YARA) or batched atoms (Suricata)."""
        cmd = [executables["bgparse"]] + search_args + [index]

        process = subprocess.run(cmd, capture_output=True)  # noqa: S603

        if process.returncode != 0:
            raise BiggrepException(f"bgparse returned exit code {process.returncode}. Args: {cmd}\n{process.stderr}")

        if b"<error>" in process.stderr:
            error_message = process.stderr.decode().split("<error>", 1)[1].split(":", 1)[1].split("\n")[0]
            raise BiggrepException(
                f"bgparse error:{error_message} - errored while searching for {rule_name} in {index}"
            )

        new_matches, new_cfg = _process_bgparse_output(
            process.stdout,
            rule_name,
            rule_matches.get(rule_name, []),
            file_config,
        )

        with lock:
            rule_matches.setdefault(rule_name, []).extend(new_matches)
            for path, cfg in new_cfg.items():
                file_config.setdefault(path, {}).update(cfg)

        return new_matches

    # Build all bgparse jobs
    jobs = []

    for index in indices:
        for rule_name, atoms in rule_atoms.items():
            if query_type == QueryTypeEnum.SURICATA:
                # SURICATA → batch all atoms
                search_args = []
                for atom in atoms:
                    search_args += ["-s", binascii.b2a_hex(atom).upper().decode()]
                jobs.append((index, rule_name, search_args))

            else:
                # YARA → atom‑by‑atom
                for atom in atoms:
                    search_args = ["-s", binascii.b2a_hex(atom).upper().decode()]
                    jobs.append((index, rule_name, search_args))

    # Execute in parallel
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for index, rule_name, search_args in jobs:
            futures.append(executor.submit(run_single_bgparse, index, rule_name, search_args))

        for future in as_completed(futures):
            future.result()
            searches_complete += 1
            progress_callback(
                SearchPhaseEnum.BROAD_PHASE,
                searches_complete,
                total_jobs,
                None,
            )

    if not rule_matches:
        raise NoIndexMatchesException("Search aborted due to index matches.")

    return rule_matches, file_config


def _process_bgparse_output(
    output: bytes, rule_name: str, file_matches: list[str], file_config: FileConfig
) -> tuple[RuleFileMatches, FileConfig]:
    """Turn bgparse stdout into a list of matching files and their config."""
    new_match_paths: list[str] = []

    if output:
        for line in output.splitlines():
            line = line.rstrip()
            if len(line) > 0:
                path = line.split(b",")[0].decode()
                if path not in file_matches:
                    new_match_paths.append(path)

                if path not in file_config:
                    file_config[path] = {}
                    storage_config_byte_list = line.split(b",")[1:-1]
                    for storage_config_bytes in storage_config_byte_list:
                        key_value = storage_config_bytes.split(b"=")
                        if len(key_value) == 2:
                            file_config[path][key_value[0]] = key_value[1]
                        else:
                            raise FileConfigReadException(f"Could not read file config from index for {path}")
    return (new_match_paths, file_config)


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
