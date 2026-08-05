"""High-level search interface for querying across existing .bgi indexes."""

import binascii
import ctypes
import gc
import hashlib
import logging
import os
import subprocess  # noqa: S404  # nosec: B404
import tempfile
import time
from collections import defaultdict
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from itertools import islice
from threading import Event

import yara
from prometheus_client import Counter, Histogram

from azul_plugin_retrohunt.retrohunt import CancelException
from azul_plugin_retrohunt.settings import RetrohuntSettings

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
from .yara_parse import AndNode, OrNode, RuleSearchPlans, StringNode, parse_yara_rules

stop_event = Event()
logger = logging.getLogger("bigyara.search")

# Python's garbage collector does not return most large bytes/native YARA
# allocations to the operating system. On glibc Linux, malloc_trim() releases
# free heap pages after a bounded narrow-phase batch has fully drained.
try:
    _libc = ctypes.CDLL(None)
    _malloc_trim = getattr(_libc, "malloc_trim", None)
    if _malloc_trim is not None:
        _malloc_trim.argtypes = [ctypes.c_size_t]
        _malloc_trim.restype = ctypes.c_int
except (OSError, AttributeError):
    _malloc_trim = None


def release_unused_memory() -> None:
    """Collect Python garbage and return free glibc heap pages when supported."""
    gc.collect()

    if _malloc_trim is not None:
        try:
            _malloc_trim(0)
        except (OSError, ValueError):
            logger.debug("malloc_trim failed", exc_info=True)


def _current_rss_mib() -> float | None:
    """Return current resident memory in MiB on Linux, otherwise None."""
    try:
        with open("/proc/self/statm", encoding="utf-8") as statm:
            resident_pages = int(statm.read().split()[1])
        return resident_pages * os.sysconf("SC_PAGE_SIZE") / (1024 * 1024)
    except (OSError, ValueError, IndexError):
        return None


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
    data_release_callback=None,
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

    def checked_data_callback(path: str, config: dict[bytes, bytes]) -> bytes:
        data: bytes = None

        if data_callback:
            try:
                data = data_callback(path, config)
            except CancelException:
                raise
            except Exception as e:
                raise DataCallbackException("Exception in data callback") from e
        else:
            raise ValueError("Invalid data callback")
        return data

    def checked_data_release_callback(path: str, matched: bool) -> None:
        if data_release_callback:
            try:
                data_release_callback(path, matched)
            except CancelException:
                raise
            except Exception as e:
                raise DataCallbackException("Exception in data release callback") from e

    if query_type == QueryTypeEnum.STRING:
        # string searches don't actually require the file data to succeed,
        # therefore the data callback is not used.
        if data_callback:
            logger.debug("Data callback is not used for string searches.")

    query_hash = hashlib.sha256(query.encode()).hexdigest()

    rule_atoms, rule_content, rule_search_plans = _atom_parse(query, query_type, checked_progress_callback)
    logger.info("Starting broad search")

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

    # Broad-phase planner structures are no longer needed before file bodies
    # are downloaded, so release them before narrow-phase memory rises.
    del rule_atoms
    del rule_search_plans
    release_unused_memory()

    logger.info("Starting narrow search")

    with prom_narrow_phase_duration.labels(query_hash=query_hash).time():
        rule_matches = _narrow_phase_search(
            query_type,
            rule_matches,
            rule_content,
            file_config,
            checked_data_callback,
            checked_progress_callback,
            query_hash=query_hash,
            data_release_callback=checked_data_release_callback,
        )

    file_config.clear()
    release_unused_memory()
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


def _string_names_for_group(plan, group_idx: int) -> list[str]:
    """Return the YARA string names associated with an atom group for logging."""
    return sorted(string_name for string_name, group_ids in plan.string_groups.items() if group_idx in group_ids)


def _format_group_atoms(plan, group_ids: list[int] | set[int]) -> str:
    """Format selected broad-phase groups, YARA strings, and exact atoms."""
    formatted_groups = []

    for group_idx in sorted(set(group_ids)):
        string_names = _string_names_for_group(plan, group_idx)
        string_label = ", ".join(string_names) if string_names else "unmapped string"
        atoms = ", ".join(repr(atom) for atom in sorted(plan.groups[group_idx]))
        formatted_groups.append(f"group {group_idx} ({string_label}) -> [{atoms}]")

    return "; ".join(formatted_groups)


def _format_or_clause(plan, group_ids: list[int]) -> str:
    """Format the YARA string names represented by a mandatory OR clause."""
    selected_group_ids = set(group_ids)
    clause_strings = []

    for string_name, string_group_ids in plan.string_groups.items():
        valid_group_ids = [group_idx for group_idx in string_group_ids if 0 <= group_idx < len(plan.groups)]

        if valid_group_ids and set(valid_group_ids).issubset(selected_group_ids):
            clause_strings.append((min(valid_group_ids), string_name))

    ordered_names = [string_name for _first_group_idx, string_name in sorted(clause_strings)]

    if not ordered_names:
        return f"groups {sorted(selected_group_ids)}"

    return "(" + " OR ".join(ordered_names) + ")"


_DEFAULT_MAX_REQUIRED_STRINGS_PER_AND_SEARCH = 4
_DEFAULT_MAX_REQUIRED_STRING_SEARCHES_PER_INDEX = 64
_DEFAULT_MAX_BROAD_PHASE_WORKERS = 1
_DEFAULT_MAX_BROAD_PHASE_TASKS = 10_000
_DEFAULT_MAX_NARROW_PHASE_INFLIGHT_FILES = 3
_DEFAULT_NARROW_PHASE_CLEANUP_MULTIPLIER = 4


def _positive_int_setting(settings, name: str, default: int) -> int:
    """Read a positive integer setting, falling back safely when invalid."""
    value = getattr(settings, name, default)

    try:
        parsed_value = int(value)
    except (TypeError, ValueError):
        logger.warning(
            "Invalid %s=%r; using default %d",
            name,
            value,
            default,
        )
        return default

    if parsed_value < 1:
        logger.warning(
            "Invalid %s=%r; value must be at least 1. Using default %d",
            name,
            value,
            default,
        )
        return default

    return parsed_value


def _bgparse_search_string(atoms: list[bytes]) -> str:
    """Return deduplicated bgparse -s arguments for an AND atom group."""
    unique_atoms = dict.fromkeys(atoms)
    return "".join(f"-s{binascii.b2a_hex(atom).upper().decode()} " for atom in unique_atoms)


def _valid_group_ids(plan, group_ids) -> list[int]:
    """Return unique, non-empty atom-group IDs that exist in the plan."""
    return list(
        dict.fromkeys(
            group_idx for group_idx in group_ids if 0 <= group_idx < len(plan.groups) and plan.groups[group_idx]
        )
    )


def _select_required_string_stages(
    plan,
    max_strings: int,
    max_searches_per_index: int,
):
    """Select a bounded set of mandatory strings for linear broad-phase filtering.

    Each selected string becomes one stage. Searches inside a stage are OR
    alternatives and are unioned. Candidate sets from separate mandatory
    strings are intersected. Because every selected string is mandatory in the
    original YARA condition, this can only add narrow-phase candidates; it
    cannot exclude a genuine match.
    """
    candidates = []
    unusable_strings = []

    for string_name in sorted(plan.required_strings):
        valid_group_ids = _valid_group_ids(
            plan,
            plan.string_groups.get(string_name, []),
        )

        if not valid_group_ids:
            unusable_strings.append(string_name)
            continue

        max_group_atom_count = max(len(plan.groups[group_idx]) for group_idx in valid_group_ids)
        longest_atom_size = max(len(atom) for group_idx in valid_group_ids for atom in plan.groups[group_idx])
        first_group_idx = min(valid_group_ids)

        candidates.append(
            (
                string_name,
                valid_group_ids,
                max_group_atom_count,
                longest_atom_size,
                first_group_idx,
            )
        )

    if not candidates:
        return [], unusable_strings, 0, False

    total_available_searches = sum(len(candidate[1]) for candidate in candidates)

    # Prefer low-cost mandatory strings first. Longer atoms are favoured when
    # two strings have the same number of alternatives and atoms.
    ranked_candidates = sorted(
        candidates,
        key=lambda candidate: (
            len(candidate[1]),
            candidate[2],
            -candidate[3],
            candidate[4],
            candidate[0],
        ),
    )

    selected = []
    selected_search_count = 0

    for candidate in ranked_candidates:
        if len(selected) >= max_strings:
            break

        candidate_search_count = len(candidate[1])
        if selected_search_count + candidate_search_count > max_searches_per_index:
            continue

        selected.append(candidate)
        selected_search_count += candidate_search_count

    forced_single_string = False
    if not selected:
        # Keep one safe mandatory filter even when its alternatives exceed the
        # preferred per-index budget. The global task limit still prevents an
        # unbounded plan from being executed.
        selected = [ranked_candidates[0]]
        selected_search_count = len(selected[0][1])
        forced_single_string = True

    # Execute the strongest-looking selected filter first so the retained
    # candidate/config set is as small as possible before later intersections.
    selected.sort(
        key=lambda candidate: (
            -candidate[3],
            -candidate[2],
            len(candidate[1]),
            candidate[4],
            candidate[0],
        )
    )

    return selected, unusable_strings, total_available_searches, forced_single_string


# FUTURE: investigate whether there is an alternative to biggrep that allows
#         batched searches as an OR on those searches.
def _run_bgparse_task(
    bgparse_exec,
    index,
    rule_name,
    search_id,
    search_string,
    query_hash,
    store_config,
    allowed_paths,
):
    """Run one bgparse process and stream its output into parsed results.

    stdout is consumed line by line instead of being retained as one large
    bytes object. stderr is written to a temporary file so neither pipe can
    fill while bgparse is running.
    """
    cmd = f"{bgparse_exec} {search_string}{index}"
    task_config: FileConfig = {}

    with tempfile.TemporaryFile() as stderr_file:
        process = subprocess.Popen(  # noqa: S602  # nosec: B602
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=stderr_file,
        )

        if process.stdout is None:
            process.terminate()
            process.wait()
            raise BiggrepException("bgparse stdout pipe was not created.")

        try:
            new_matches, task_config = _process_bgparse_lines(
                process.stdout,
                rule_name,
                task_config,
                query_hash=query_hash,
                index_path=index,
                store_config=store_config,
                allowed_paths=allowed_paths,
            )
        finally:
            process.stdout.close()

        returncode = process.wait()
        stderr_file.seek(0)
        stderr = stderr_file.read()

    if stop_event.is_set():
        raise CancelException("Broadphase cancelled by user.")

    return (
        rule_name,
        search_id,
        index,
        search_string,
        returncode,
        new_matches,
        task_config,
        stderr,
    )


def _run_bgparse_task_args(
    task: tuple,
):
    """Unpack a broad-phase task for the bounded thread executor."""
    return _run_bgparse_task(*task)


def _broad_phase_search(
    query_type: int,
    indices: list[str],
    rule_search_plans: RuleSearchPlans,
    progress_callback: ProgressCallback,
    query_hash: str,
) -> tuple[RuleFileMatches, FileConfig]:
    """Run resource-bounded broad-phase searches and combine their candidates.

    A search stage is an OR of alternative atom groups. Required-string stages
    are intersected because every selected string is mandatory. All other modes
    preserve the existing union behaviour.
    """
    if query_type == QueryTypeEnum.SURICATA:
        raise NotImplementedError("Suricata broad-phase search is not implemented yet.")

    bgparse_exec = executables["bgparse"]
    logger.debug("Rule search plans broad phase: %s", rule_search_plans)

    settings = RetrohuntSettings().search_settings
    max_required_strings = _positive_int_setting(
        settings,
        "max_required_strings_per_and_search",
        _DEFAULT_MAX_REQUIRED_STRINGS_PER_AND_SEARCH,
    )
    max_required_string_searches = _positive_int_setting(
        settings,
        "max_required_string_searches_per_index",
        _DEFAULT_MAX_REQUIRED_STRING_SEARCHES_PER_INDEX,
    )
    configured_broad_workers = _positive_int_setting(
        settings,
        "max_broad_phase_workers",
        _DEFAULT_MAX_BROAD_PHASE_WORKERS,
    )
    max_broad_phase_tasks = _positive_int_setting(
        settings,
        "max_broad_phase_tasks",
        _DEFAULT_MAX_BROAD_PHASE_TASKS,
    )
    broad_phase_workers = min(configured_broad_workers, os.cpu_count() or 1)

    # Each rule plan contains one or more stages. Searches within a stage are
    # OR alternatives. Required-string stages are intersected with one another.
    broad_plans: dict[str, dict] = {}

    for rule_name, plan in rule_search_plans.items():
        required_string_stages = []
        unusable_required_strings = []
        total_required_searches = 0
        forced_single_required_string = False

        if getattr(plan, "required_strings", None):
            (
                selected_required_strings,
                unusable_required_strings,
                total_required_searches,
                forced_single_required_string,
            ) = _select_required_string_stages(
                plan,
                max_required_strings,
                max_required_string_searches,
            )

            for string_name, group_ids, _atom_count, _longest_atom, _first_group in selected_required_strings:
                required_string_stages.append(
                    {
                        "label": string_name,
                        "group_ids": group_ids,
                        "searches": [
                            (group_idx, _bgparse_search_string(plan.groups[group_idx])) for group_idx in group_ids
                        ],
                    }
                )

        if required_string_stages:
            broad_plans[rule_name] = {
                "mode": "required_strings",
                "combine": "intersection",
                "stages": required_string_stages,
            }

            selected_names = [stage["label"] for stage in required_string_stages]
            selected_searches = sum(len(stage["searches"]) for stage in required_string_stages)
            selected_group_ids = {group_idx for stage in required_string_stages for group_idx in stage["group_ids"]}

            logger.info(
                'Rule "%s": selected %d of %d mandatory strings (%s). '
                "Their %d alternative atom-group searches per index will be unioned "
                "within each string and intersected across strings. The complete usable "
                "mandatory-string plan contains %d searches per index; configured limits "
                "are %d strings and %d searches per index.",
                rule_name,
                len(required_string_stages),
                len(plan.required_strings),
                ", ".join(selected_names),
                selected_searches,
                total_required_searches,
                max_required_strings,
                max_required_string_searches,
            )

            if unusable_required_strings:
                logger.info(
                    'Rule "%s": mandatory strings without usable atom groups were omitted '
                    "from broad phase: %s. Narrow phase still evaluates the complete rule.",
                    rule_name,
                    ", ".join(unusable_required_strings),
                )

            if forced_single_required_string:
                logger.warning(
                    'Rule "%s": the lowest-cost mandatory string exceeds '
                    "max_required_string_searches_per_index=%d. It was selected alone; "
                    "the global max_broad_phase_tasks limit still applies.",
                    rule_name,
                    max_required_string_searches,
                )

            logger.info(
                'Rule "%s": exact atom groups selected: %s',
                rule_name,
                _format_group_atoms(plan, selected_group_ids),
            )
            continue

        required_or_clauses: list[list[int]] = []
        unsafe_required_or_clause = False
        condition_ast = getattr(plan, "condition_ast", None)

        # For ($a or $b) and ($c or $d), each direct OR child is mandatory.
        # A complete clause is safe to search because every final match must
        # satisfy that whole clause.
        if isinstance(condition_ast, AndNode):
            for child in condition_ast.children:
                if not isinstance(child, OrNode):
                    continue

                if not child.children or not all(isinstance(sub, StringNode) for sub in child.children):
                    unsafe_required_or_clause = True
                    continue

                clause_group_ids = []
                clause_usable = True

                for sub in child.children:
                    valid_group_ids = _valid_group_ids(
                        plan,
                        plan.string_groups.get(sub.string_name, []),
                    )
                    if not valid_group_ids:
                        clause_usable = False
                        unsafe_required_or_clause = True
                        break
                    clause_group_ids.extend(valid_group_ids)

                if clause_usable:
                    clause_group_ids = list(dict.fromkeys(clause_group_ids))
                    if clause_group_ids:
                        required_or_clauses.append(clause_group_ids)

        if required_or_clauses:
            selected_group_ids = min(
                required_or_clauses,
                key=lambda clause: (
                    sum(len(plan.groups[group_idx]) for group_idx in clause),
                    len(clause),
                    tuple(clause),
                ),
            )
            selected_clause = _format_or_clause(plan, selected_group_ids)

            broad_plans[rule_name] = {
                "mode": "required_or_clause",
                "combine": "union",
                "stages": [
                    {
                        "label": selected_clause,
                        "group_ids": selected_group_ids,
                        "searches": [
                            (group_idx, _bgparse_search_string(plan.groups[group_idx]))
                            for group_idx in selected_group_ids
                        ],
                    }
                ],
            }

            logger.info(
                'Rule "%s": selected mandatory OR clause %s from %d complete '
                "searchable clause(s). Its %d atom-group alternatives will be unioned.",
                rule_name,
                selected_clause,
                len(required_or_clauses),
                len(selected_group_ids),
            )
            logger.info(
                'Rule "%s": exact atom groups selected for %s: %s',
                rule_name,
                selected_clause,
                _format_group_atoms(plan, selected_group_ids),
            )
            continue

        if unsafe_required_or_clause:
            fallback_group_ids = [group_idx for group_idx, group in enumerate(plan.groups) if group]
            broad_plans[rule_name] = {
                "mode": "fallback",
                "combine": "union",
                "stages": [
                    {
                        "label": "all searchable atom groups",
                        "group_ids": fallback_group_ids,
                        "searches": [
                            (group_idx, _bgparse_search_string(plan.groups[group_idx]))
                            for group_idx in fallback_group_ids
                        ],
                    }
                ],
            }

            logger.info(
                'Rule "%s": a mandatory OR clause contained an unrecognised, '
                "non-string, or unsearchable alternative. Falling back to OR-searching "
                "all %d non-empty atom groups.",
                rule_name,
                len(fallback_group_ids),
            )
            logger.info(
                'Rule "%s": exact atom groups selected by fallback: %s',
                rule_name,
                _format_group_atoms(plan, fallback_group_ids),
            )
            continue

        required_group_ids: set[int] = set()
        for required_group in getattr(plan, "required_groups", None) or []:
            if not required_group:
                continue
            for group_idx, actual_group in enumerate(plan.groups):
                if actual_group and set(actual_group) == set(required_group):
                    required_group_ids.add(group_idx)
                    break

        if required_group_ids:
            selected_group_ids = sorted(required_group_ids)
            broad_plans[rule_name] = {
                "mode": "required_groups",
                "combine": "union",
                "stages": [
                    {
                        "label": "parser-required groups",
                        "group_ids": selected_group_ids,
                        "searches": [
                            (group_idx, _bgparse_search_string(plan.groups[group_idx]))
                            for group_idx in selected_group_ids
                        ],
                    }
                ],
            }

            logger.info(
                'Rule "%s": using %d parser-required atom groups and unioning their candidate files.',
                rule_name,
                len(selected_group_ids),
            )
            logger.info(
                'Rule "%s": exact parser-required atom groups selected: %s',
                rule_name,
                _format_group_atoms(plan, selected_group_ids),
            )
            continue

        fallback_group_ids = [group_idx for group_idx, group in enumerate(plan.groups) if group]
        broad_plans[rule_name] = {
            "mode": "fallback",
            "combine": "union",
            "stages": [
                {
                    "label": "all searchable atom groups",
                    "group_ids": fallback_group_ids,
                    "searches": [
                        (group_idx, _bgparse_search_string(plan.groups[group_idx])) for group_idx in fallback_group_ids
                    ],
                }
            ],
        }

        logger.info(
            'Rule "%s": no safe mandatory-string, mandatory-OR, or parser-required '
            "filter was available. Falling back to OR-searching all %d non-empty "
            "atom groups.",
            rule_name,
            len(fallback_group_ids),
        )
        logger.info(
            'Rule "%s": exact atom groups selected by fallback: %s',
            rule_name,
            _format_group_atoms(plan, fallback_group_ids),
        )

    searches_per_index = sum(
        len(stage["searches"]) for rule_plan in broad_plans.values() for stage in rule_plan["stages"]
    )
    search_count = len(indices) * searches_per_index

    if search_count == 0:
        # Preserve established plain-string behaviour: plain string atoms are
        # parsed but do not currently produce an optimised broad-phase plan.
        if query_type == QueryTypeEnum.STRING:
            raise NoIndexMatchesException("Search aborted due to no index matches.")

        raise NoAtomException("Broad-phase planner generated no usable atom searches.")

    if search_count > max_broad_phase_tasks:
        raise BiggrepException(
            f"Broad-phase plan would generate {search_count} tasks across "
            f"{len(indices)} indexes, exceeding the configured "
            f"max_broad_phase_tasks limit of {max_broad_phase_tasks}. "
            "Reduce the number of rules or selected atom groups, or increase "
            "the limit if the additional broad-phase load is acceptable."
        )

    logger.info(
        "Broad search starting: %d tasks across %d indexes using up to %d workers",
        search_count,
        len(indices),
        broad_phase_workers,
    )

    searches_complete = 0
    next_progress_percent = 20
    progress_callback(SearchPhaseEnum.BROAD_PHASE, 0, search_count, None)

    file_config: FileConfig = {}
    rule_matches: RuleFileMatches = {}
    start = time.time()

    for rule_name, rule_plan in broad_plans.items():
        combine = rule_plan["combine"]
        rule_candidates: set[str] | None = None
        rule_config: FileConfig = {}

        for stage_number, stage in enumerate(rule_plan["stages"], start=1):
            stage_searches = stage["searches"]
            stage_task_count = len(indices) * len(stage_searches)
            stage_matches: set[str] = set()
            collect_stage_config = combine == "union" or stage_number == 1

            # For later mandatory-string stages, paths outside the current
            # intersection can never reach narrow phase. Filtering them while
            # stdout is streamed prevents large temporary stage result sets.
            allowed_paths = rule_candidates if combine == "intersection" and rule_candidates is not None else None

            def iter_stage_tasks(
                stage_searches=stage_searches,
                rule_name=rule_name,
                collect_stage_config=collect_stage_config,
                allowed_paths=allowed_paths,
            ):
                for index in indices:
                    for search_id, search_string in stage_searches:
                        yield (
                            bgparse_exec,
                            index,
                            rule_name,
                            search_id,
                            search_string,
                            query_hash,
                            collect_stage_config,
                            allowed_paths,
                        )

            task_iterator = iter(iter_stage_tasks())
            pending = {}

            # Use threads only to wait on independent bgparse subprocesses.
            # Unlike multiprocessing.Pool, this does not retain forked Python
            # workers or pickle complete stdout buffers between processes.
            # The executor is deliberately recreated for every stage so any
            # Future-held memory is released before the next intersection.
            with ThreadPoolExecutor(max_workers=broad_phase_workers) as executor:
                for _ in range(min(broad_phase_workers, stage_task_count)):
                    try:
                        task = next(task_iterator)
                    except StopIteration:
                        break
                    pending[executor.submit(_run_bgparse_task_args, task)] = task

                stage_complete = 0

                while pending:
                    completed_futures, _ = wait(
                        tuple(pending),
                        timeout=0.5,
                        return_when=FIRST_COMPLETED,
                    )

                    if not completed_futures:
                        progress_callback(
                            SearchPhaseEnum.BROAD_PHASE,
                            searches_complete,
                            search_count,
                            None,
                        )
                        if stop_event.is_set():
                            raise CancelException("Broadphase cancelled by user.") from None
                        continue

                    for future in completed_futures:
                        pending.pop(future, None)
                        (
                            completed_rule_name,
                            _search_id,
                            index,
                            search_string,
                            returncode,
                            new_matches,
                            task_config,
                            stderr,
                        ) = future.result()

                        if returncode != 0:
                            raise BiggrepException(
                                f"bgparse returned exit code {returncode}. Args: {search_string}{index}\n{stderr}"
                            )

                        if b"<error>" in stderr:
                            error_text = stderr.decode(errors="replace")
                            error_message = error_text.split("<error>", 1)[1]
                            if ":" in error_message:
                                error_message = error_message.split(":", 1)[1]
                            error_message = error_message.split("\n", 1)[0]
                            raise BiggrepException(
                                f"bgparse error:{error_message} - errored while "
                                f"searching for {completed_rule_name} in {index}"
                            )

                        stage_matches.update(new_matches)

                        if task_config:
                            for path, cfg in task_config.items():
                                rule_config.setdefault(path, cfg)

                        stage_complete += 1
                        searches_complete += 1

                        progress_callback(
                            SearchPhaseEnum.BROAD_PHASE,
                            searches_complete,
                            search_count,
                            (completed_rule_name, new_matches),
                        )

                        current_percent = (searches_complete * 100) // search_count
                        while current_percent >= next_progress_percent:
                            logger.info(
                                "Broad search %d%% complete: %d/%d tasks processed",
                                next_progress_percent,
                                searches_complete,
                                search_count,
                            )
                            next_progress_percent += 20

                        if stop_event.is_set():
                            raise CancelException("Broadphase cancelled by user.")

                        try:
                            task = next(task_iterator)
                        except StopIteration:
                            task = None

                        if task is not None:
                            pending[executor.submit(_run_bgparse_task_args, task)] = task

                        del new_matches
                        del task_config
                        del stderr

            if stage_complete != stage_task_count:
                raise BiggrepException(
                    f"Broad-phase stage completed {stage_complete} of {stage_task_count} expected tasks."
                )

            del pending
            del task_iterator
            gc.collect()

            if combine == "intersection":
                if rule_candidates is None:
                    rule_candidates = stage_matches
                else:
                    rule_candidates.intersection_update(stage_matches)

                if rule_config:
                    for path in list(rule_config):
                        if path not in rule_candidates:
                            del rule_config[path]

                logger.info(
                    'Rule "%s": mandatory string %s OR-union produced %d '
                    "relevant candidates; intersection after %d/%d strings "
                    "contains %d.",
                    rule_name,
                    stage["label"],
                    len(stage_matches),
                    stage_number,
                    len(rule_plan["stages"]),
                    len(rule_candidates),
                )
            else:
                if rule_candidates is None:
                    rule_candidates = stage_matches
                else:
                    rule_candidates.update(stage_matches)

            del stage_matches
            gc.collect()
            logger.debug(
                'Rule "%s": broad-phase stage %d executor exited and memory cleanup completed',
                rule_name,
                stage_number,
            )

        final_candidates = rule_candidates or set()
        rule_matches[rule_name] = list(final_candidates)

        for path in final_candidates:
            if path in rule_config:
                file_config[path] = rule_config[path]

        logger.debug(
            'Rule "%s": broad-phase mode %s produced %d final candidates',
            rule_name,
            rule_plan["mode"],
            len(final_candidates),
        )

    duration = time.time() - start
    prom_bgparse_duration.labels(query_hash=query_hash).observe(duration)
    logger.debug("Total BigGrep parse time: %s", duration)

    logger.debug("All index searches completed")

    if all(len(matches) == 0 for matches in rule_matches.values()):
        raise NoIndexMatchesException("Search aborted due to no index matches.")

    return rule_matches, file_config


def _process_bgparse_lines(
    lines,
    rule_name: str,
    file_config: FileConfig,
    query_hash: str,
    index_path: str,
    store_config: bool = True,
    allowed_paths: set[str] | None = None,
) -> tuple[list[str], FileConfig]:
    """Parse an iterable of bgparse output lines incrementally."""
    new_match_paths = []

    for line in lines:
        line = line.rstrip()
        if not line:
            continue

        parts = line.split(b",")
        path = parts[0].decode()

        if allowed_paths is not None and path not in allowed_paths:
            continue

        new_match_paths.append(path)

        if store_config and path not in file_config:
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

        if stop_event.is_set():
            raise CancelException("Broadphase cancelled by user.")

    return new_match_paths, file_config


def _process_bgparse_output(
    output: bytes,
    rule_name: str,
    file_config: FileConfig,
    query_hash: str,
    index_path: str,
    store_config: bool = True,
) -> tuple[list[str], FileConfig]:
    """Compatibility wrapper for tests and callers supplying complete bytes."""
    return _process_bgparse_lines(
        output.splitlines(),
        rule_name,
        file_config,
        query_hash=query_hash,
        index_path=index_path,
        store_config=store_config,
    )


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
    data_release_callback=None,
) -> RuleFileMatches:
    """Narrow phase search using whichever tool is relevant to the search type."""
    if queryType == QueryTypeEnum.STRING:
        return rule_matches

    if data_release_callback is None:

        def data_release_callback(_path: str, _matched: bool) -> None:
            return None

    # Convert rule matches to sets, then immediately release the broad-phase
    # list containers. The path strings themselves are reused by the sets.
    rule_matches_sets: dict[str, set[str]] = {rule_name: set(paths) for rule_name, paths in rule_matches.items()}
    rule_matches.clear()

    # Invert mapping: file -> rules. This mapping is destructively drained in
    # bounded batches so processed candidates do not remain referenced.
    file_to_rules: dict[str, set[str]] = defaultdict(set)
    for rule_name, paths in rule_matches_sets.items():
        for file_path in paths:
            file_to_rules[file_path].add(rule_name)

    # Precompile YARA rules once per hunt.
    compiled_yara_rules = {}
    if queryType == QueryTypeEnum.YARA:
        for rule_name, content in rule_content.items():
            if not content.startswith('import "pe"\n'):
                content = 'import "pe"\n' + content
            compiled_yara_rules[rule_name] = yara.compile(source=content)

    # Bind metric children once instead of performing label lookups per file.
    missing_files_metric = prom_missing_files.labels(query_hash=query_hash)
    io_duration_metric = prom_narrow_io_duration.labels(query_hash=query_hash)
    io_bytes_metric = prom_narrow_io_bytes.labels(query_hash=query_hash)
    cpu_duration_metrics = {
        rule_name: prom_narrow_cpu_duration.labels(
            query_hash=query_hash,
            rule_name=rule_name,
        )
        for rule_name in rule_matches_sets
    }

    search_settings = RetrohuntSettings().search_settings
    configured_threads = _positive_int_setting(
        search_settings,
        "max_thread_count",
        1,
    )
    default_inflight_files = min(
        configured_threads,
        _DEFAULT_MAX_NARROW_PHASE_INFLIGHT_FILES,
    )
    max_inflight_files = _positive_int_setting(
        search_settings,
        "max_narrow_phase_inflight_files",
        default_inflight_files,
    )

    total_files = len(file_to_rules)
    active_workers = max(
        1,
        min(configured_threads, max_inflight_files, total_files or 1),
    )
    cleanup_batch_size = _positive_int_setting(
        search_settings,
        "narrow_phase_cleanup_batch_size",
        active_workers * _DEFAULT_NARROW_PHASE_CLEANUP_MULTIPLIER,
    )
    cleanup_batch_size = max(active_workers, cleanup_batch_size)

    # Worker function. A worker holds at most one complete file body. data is
    # deleted in finally so YARA timeouts/errors cannot pin a large bytes object
    # inside a traceback retained by a Future.
    def worker(file_path: str, rules_for_file: set[str]):
        if stop_event.is_set():
            raise CancelException("Narrow phase cancelled by user.")

        # Each config entry is needed only until its file has been fetched.
        # Popping here lets the broad-phase metadata table shrink continuously.
        cfg = file_config.pop(file_path, None)
        data = None

        try:
            io_start = time.time()
            data = data_callback(file_path, cfg)
            io_duration = time.time() - io_start

            # Cancellation may have been requested while the dispatcher call
            # was blocked.
            if stop_event.is_set():
                raise CancelException("Narrow phase cancelled by user.")

            data_len = len(data) if data else 0
            if not data:
                missing_files_metric.inc()
                return ("missing", file_path, rules_for_file, None, io_duration, data_len)

            results = []
            for rule_name in rules_for_file:
                if stop_event.is_set():
                    raise CancelException("Narrow phase cancelled by user.")

                if queryType == QueryTypeEnum.YARA:
                    with cpu_duration_metrics[rule_name].time():
                        matched = bool(
                            compiled_yara_rules[rule_name].match(
                                data=data,
                                callback=yara_callback,
                                which_callbacks=yara.CALLBACK_MATCHES,
                                fast=True,
                                timeout=60,
                            )
                        )
                elif queryType == QueryTypeEnum.SURICATA:
                    matched = _run_suricata(rule_content[rule_name], file_path, data)

                results.append((rule_name, matched))

            return ("ok", file_path, rules_for_file, results, io_duration, data_len)
        finally:
            # bytes objects are not cyclic garbage. Removing the last worker
            # reference here is what makes the buffer immediately reclaimable.
            data = None
            cfg = None

    def worker_task(task: tuple[str, set[str]]):
        file_path, rules_for_file = task
        return worker(file_path, rules_for_file)

    # Precompute progress totals.
    total_jobs = sum(len(paths) for paths in rule_matches_sets.values())
    jobs_complete = 0
    files_complete = 0
    next_progress_percent = 5

    progress_callback(SearchPhaseEnum.NARROW_PHASE, 0, total_jobs, None)

    logger.info(
        "Narrow search starting: %d unique files across %d rule/file jobs; "
        "%d threads configured, %d large files allowed in flight, cleanup every %d files.",
        total_files,
        total_jobs,
        configured_threads,
        active_workers,
        cleanup_batch_size,
    )

    rss_mib = _current_rss_mib()
    if rss_mib is not None:
        logger.info("Narrow search starting process RSS: %.1f MiB", rss_mib)

    def process_batch(
        executor: ThreadPoolExecutor,
        batch: dict[str, set[str]],
    ) -> None:
        """Process one bounded batch and release per-file metadata immediately."""
        nonlocal jobs_complete
        nonlocal total_jobs
        nonlocal files_complete
        nonlocal next_progress_percent

        futures = {executor.submit(worker_task, item): item for item in batch.items()}

        try:
            for future in as_completed(tuple(futures)):
                task = futures.pop(future, None)

                try:
                    status, file_path, rules_for_file, results, io_duration, data_len = future.result()
                except Exception:
                    # The worker may have fetched metadata before failing. Do
                    # not leave it retained for the rest of the hunt.
                    if task is not None:
                        data_release_callback(task[0], False)
                    raise

                file_matched = False

                try:
                    io_duration_metric.observe(io_duration)
                    io_bytes_metric.inc(data_len)

                    if stop_event.is_set():
                        raise CancelException("Narrow phase cancelled by user.")

                    files_complete += 1
                    current_percent = (files_complete * 100) // total_files if total_files else 100

                    while current_percent >= next_progress_percent:
                        logger.info(
                            "Narrow search %d%% complete: %d/%d files processed",
                            next_progress_percent,
                            files_complete,
                            total_files,
                        )
                        next_progress_percent += 5

                    if status == "missing":
                        for rule_name in rules_for_file:
                            total_jobs -= 1
                            rule_matches_sets[rule_name].discard(file_path)

                        progress_callback(
                            SearchPhaseEnum.NARROW_PHASE,
                            jobs_complete,
                            total_jobs,
                            None,
                        )
                    else:
                        for rule_name, matched in results:
                            jobs_complete += 1
                            file_matched = file_matched or matched

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
                finally:
                    # The worker-level callback stores metadata only long
                    # enough for matched progress callbacks to consume it.
                    data_release_callback(file_path, file_matched)
                    results = None
                    rules_for_file = None
                    task = None
        finally:
            futures.clear()

    batch_count = 0

    # One executor is reused for the entire hunt. Recreating pools for every
    # tiny chunk creates new native allocator arenas and is a major reason RSS
    # remains high after large-file scans.
    with ThreadPoolExecutor(max_workers=active_workers) as executor:
        for batch_count, batch in enumerate(
            _pop_dict_chunks(file_to_rules, cleanup_batch_size),
            start=1,
        ):
            logger.debug(
                "Starting narrow-phase cleanup batch %d containing %d files",
                batch_count,
                len(batch),
            )

            process_batch(executor, batch)

            batch.clear()
            release_unused_memory()

            rss_mib = _current_rss_mib()
            if rss_mib is not None:
                logger.debug(
                    "Narrow-phase cleanup batch %d completed; process RSS %.1f MiB",
                    batch_count,
                    rss_mib,
                )

    # Convert back to lists and remove empty rules.
    final_matches: RuleFileMatches = {
        rule_name: list(paths) for rule_name, paths in rule_matches_sets.items() if paths
    }

    if final_matches:
        confirmed_path_matches = sum(len(paths) for paths in final_matches.values())
        unique_file_names = {os.path.basename(path) for paths in final_matches.values() for path in paths}

        logger.info(
            "Found %d confirmed matching paths representing %d unique filenames across %d YARA rules.",
            confirmed_path_matches,
            len(unique_file_names),
            len(final_matches),
        )

        for rule_name, paths in final_matches.items():
            for path in sorted(paths):
                logger.debug(
                    'Confirmed narrow match: rule="%s" path="%s" file_id="%s"',
                    rule_name,
                    path,
                    os.path.basename(path),
                )
    else:
        logger.info("No rules matched after Narrowing.")

    # Drop native YARA objects and all candidate/config containers before the
    # final trim. Only the confirmed result lists survive this point.
    compiled_yara_rules.clear()
    cpu_duration_metrics.clear()
    file_config.clear()
    file_to_rules.clear()
    rule_matches_sets.clear()
    release_unused_memory()

    rss_mib = _current_rss_mib()
    if rss_mib is not None:
        logger.info("Narrow search cleanup completed; process RSS: %.1f MiB", rss_mib)

    return final_matches


def trigger_stop_event():
    """Set stop event for threads if user cancels manually."""
    stop_event.set()


def clear_stop_event():
    """Clear the stop event flag."""
    stop_event.clear()


def _pop_dict_chunks(
    d: dict[str, set[str]],
    chunk_size: int,
):
    """Yield bounded dictionaries while removing entries from the source."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be a positive integer")

    while d:
        batch = {}
        for _ in range(min(chunk_size, len(d))):
            file_path, rules_for_file = d.popitem()
            batch[file_path] = rules_for_file
        yield batch


def chunk_dict(
    d: dict[str, set[str]],
    chunk_size: int,
):
    """Yield dictionaries containing at most chunk_size items."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be a positive integer")

    items = iter(d.items())

    while True:
        batch = dict(islice(items, chunk_size))
        if not batch:
            return

        yield batch


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
