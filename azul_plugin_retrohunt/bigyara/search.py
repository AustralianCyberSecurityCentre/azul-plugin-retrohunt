"""High-level search interface for querying across existing .bgi indexes."""

import binascii
import hashlib
import logging
import multiprocessing
import os
import subprocess  # noqa: S404  # nosec: B404
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import islice, product
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


def _format_or_clause_choices(plan, clauses: list[list[int]]) -> str:
    """Describe the searchable mandatory OR clauses considered by the planner."""
    choices = []

    for clause in clauses:
        atom_count = sum(len(plan.groups[group_idx]) for group_idx in clause)
        choices.append(f"{_format_or_clause(plan, clause)} ({len(clause)} groups, {atom_count} atoms)")

    return "; ".join(choices)


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

    if stop_event.is_set():
        raise CancelException("Broadphase cancelled by user.")

    return (
        rule_name,
        group_idx,
        index,
        search_string,
        process.returncode,
        process.stdout,
        process.stderr,
    )


def _run_bgparse_task_args(
    task: tuple[str, str, str, int, str],
):
    """Unpack a broad-phase task for multiprocessing.imap_unordered."""
    return _run_bgparse_task(*task)


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
    logger.debug("Rule search plans broad phase: %s", rule_search_plans)

    search_strings: dict[str, list[tuple[int, str]]] = {}
    broad_phase_modes: dict[str, str] = {}
    selected_required_or_clauses: dict[str, list[int]] = {}

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
            selected_group_ids = {
                group_idx for group_options in required_string_group_options for group_idx in group_options
            }
            required_string_expression = " AND ".join(sorted(plan.required_strings))
            logger.info(
                'Rule "%s": broad-phase selection: the condition requires %s. '
                "Each broad-phase search will combine one atom option from every "
                "required string, because every final match must satisfy all of them.",
                rule_name,
                required_string_expression,
            )
            logger.info(
                'Rule "%s": exact atom groups selected: %s',
                rule_name,
                _format_group_atoms(plan, selected_group_ids),
            )
            logger.debug(
                'Rule "%s": required_strings present; generated %d combined AND bgparse searches covering %d required strings',
                rule_name,
                len(search_strings[rule_name]),
                len(plan.required_strings),
            )

        else:
            required_group_ids: set[int] = set()
            rule_required_or_clauses: list[list[int]] = []
            unsafe_required_or_clause = False

            # Preserve the direct top-level AND/OR structure from the parser.
            # For ($a or $b) and ($c or $d), this produces two mandatory OR
            # clauses instead of flattening all four strings into one large OR.
            condition_ast = getattr(plan, "condition_ast", None)
            if isinstance(condition_ast, AndNode):
                for child in condition_ast.children:
                    if not isinstance(child, OrNode):
                        continue

                    if not child.children:
                        unsafe_required_or_clause = True
                        continue

                    # Only use a clause when every alternative is a searchable
                    # string. If no other complete mandatory OR clause can be
                    # selected, mixed/unknown clauses force the full fallback.
                    if not all(isinstance(sub, StringNode) for sub in child.children):
                        unsafe_required_or_clause = True
                        continue

                    clause_group_ids: list[int] = []
                    clause_usable = True

                    for sub in child.children:
                        valid_group_ids = [
                            group_idx
                            for group_idx in plan.string_groups.get(sub.string_name, [])
                            if 0 <= group_idx < len(plan.groups)
                        ]

                        if not valid_group_ids:
                            clause_usable = False
                            unsafe_required_or_clause = True
                            break

                        clause_group_ids.extend(valid_group_ids)

                    if clause_usable:
                        unique_clause_group_ids = list(dict.fromkeys(clause_group_ids))
                        if unique_clause_group_ids:
                            rule_required_or_clauses.append(unique_clause_group_ids)
                            required_group_ids.update(unique_clause_group_ids)

            if rule_required_or_clauses:
                broad_phase_modes[rule_name] = "required_or_clause"

                # Choose one mandatory OR clause before generating any bgparse
                # tasks. Fewer atom groups means fewer OR-alternative searches.
                selected_group_ids = min(
                    rule_required_or_clauses,
                    key=lambda clause: (
                        sum(len(plan.groups[group_idx]) for group_idx in clause),
                        len(clause),
                        tuple(clause),
                    ),
                )
                selected_required_or_clauses[rule_name] = selected_group_ids

                for group_idx in sorted(selected_group_ids):
                    group = plan.groups[group_idx]
                    hex_atoms = [binascii.b2a_hex(atom).upper().decode() for atom in group]
                    search_strings[rule_name].append(
                        (
                            group_idx,
                            "".join(f"-s{hex_atom} " for hex_atom in hex_atoms),
                        )
                    )

                selected_clause = _format_or_clause(plan, selected_group_ids)
                selected_atom_count = sum(len(plan.groups[group_idx]) for group_idx in selected_group_ids)
                logger.info(
                    'Rule "%s": broad-phase selection: the condition contains %d complete, '
                    "directly searchable mandatory OR clause(s): %s. Every final match must "
                    "satisfy each mandatory clause, so searching any one complete clause is safe. "
                    "Selected %s because it has the lowest search cost (%d groups, %d atoms). "
                    "This minimises the number of broad-phase searches; it is a task-cost "
                    "heuristic and does not assume which clause will return the fewest candidates.",
                    rule_name,
                    len(rule_required_or_clauses),
                    _format_or_clause_choices(plan, rule_required_or_clauses),
                    selected_clause,
                    len(selected_group_ids),
                    selected_atom_count,
                )
                logger.info(
                    'Rule "%s": exact atom groups selected for %s: %s',
                    rule_name,
                    selected_clause,
                    _format_group_atoms(plan, selected_group_ids),
                )
                logger.debug(
                    'Rule "%s": selected required OR clause groups %s containing %d atoms; '
                    "generated %d searches instead of searching all %d mandatory OR clauses",
                    rule_name,
                    selected_group_ids,
                    sum(len(plan.groups[group_idx]) for group_idx in selected_group_ids),
                    len(search_strings[rule_name]),
                    len(rule_required_or_clauses),
                )

            else:
                if unsafe_required_or_clause:
                    broad_phase_modes[rule_name] = "fallback"

                    for group_idx, group in enumerate(plan.groups):
                        hex_atoms = [binascii.b2a_hex(atom).upper().decode() for atom in group]
                        search_strings[rule_name].append(
                            (
                                group_idx,
                                "".join(f"-s{hex_atom} " for hex_atom in hex_atoms),
                            )
                        )

                    fallback_group_ids = set(range(len(plan.groups)))
                    logger.info(
                        'Rule "%s": broad-phase selection: no complete mandatory OR clause '
                        "could be selected because at least one relevant clause contained an "
                        "unrecognised condition, a non-string alternative, or a string without "
                        "usable atoms. Falling back to OR-searching every available atom group "
                        "instead of trusting a partial clause or the parser's required_groups.",
                        rule_name,
                    )
                    logger.info(
                        'Rule "%s": exact atom groups selected by the full fallback: %s',
                        rule_name,
                        _format_group_atoms(plan, fallback_group_ids),
                    )
                    logger.debug(
                        'Rule "%s": unusable mixed/unknown mandatory OR clauses; '
                        "bypassing required_groups and generated %d fallback OR searches",
                        rule_name,
                        len(search_strings[rule_name]),
                    )
                    continue

                if getattr(plan, "required_groups", None):
                    for required_group in plan.required_groups:
                        for group_idx, actual_group in enumerate(plan.groups):
                            if set(actual_group) == set(required_group):
                                required_group_ids.add(group_idx)
                                break

                required_group_ids = {
                    group_idx for group_idx in required_group_ids if 0 <= group_idx < len(plan.groups)
                }

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
                        'Rule "%s": broad-phase selection: no directly usable required-string '
                        "plan or complete mandatory OR clause was available. The parser supplied "
                        "required atom groups, so broad phase will search all of those groups and "
                        "union their candidate files before narrow-phase verification.",
                        rule_name,
                    )
                    logger.info(
                        'Rule "%s": exact parser-required atom groups selected: %s',
                        rule_name,
                        _format_group_atoms(plan, required_group_ids),
                    )
                    logger.debug(
                        'Rule "%s": no usable required_strings/OR clauses; generated %d required_group searches',
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

                    fallback_group_ids = set(range(len(plan.groups)))
                    logger.info(
                        'Rule "%s": broad-phase selection: the condition did not provide any '
                        "safe required strings, complete mandatory OR clause, or parser-required "
                        "groups that could reduce the search. Falling back to OR-searching every "
                        "available atom group so all searchable alternatives are considered.",
                        rule_name,
                    )
                    logger.info(
                        'Rule "%s": exact atom groups selected by the all-groups fallback: %s',
                        rule_name,
                        _format_group_atoms(plan, fallback_group_ids),
                    )
                    logger.debug(
                        'Rule "%s": no required_strings/groups; generated %d fallback OR searches',
                        rule_name,
                        len(search_strings[rule_name]),
                    )

    tasks = []
    for index in indices:
        for rule_name, grouped_searches in search_strings.items():
            for search_id, search_string in grouped_searches:
                tasks.append(
                    (
                        bgparse_exec,
                        index,
                        rule_name,
                        search_id,
                        search_string,
                    )
                )

    logger.debug("Broad phase generated %d tasks", len(tasks))
    search_count = len(tasks)
    searches_complete = 0
    progress_callback(SearchPhaseEnum.BROAD_PHASE, 0, search_count, None)

    file_config: FileConfig = {}
    search_matches: dict[str, dict[int, set[str]]] = {
        rule_name: {search_id: set() for search_id, _ in grouped_searches}
        for rule_name, grouped_searches in search_strings.items()
    }

    start = time.time()

    next_progress_percent = 20

    with multiprocessing.Pool() as pool:
        # Match Pool.map's normal batching while still yielding completed
        # task results incrementally.
        process_count = multiprocessing.cpu_count()
        chunksize = max(
            1,
            (search_count + (process_count * 4) - 1) // (process_count * 4),
        )
        result_iterator = pool.imap_unordered(
            _run_bgparse_task_args,
            tasks,
            chunksize=chunksize,
        )

        while searches_complete < search_count:
            try:
                timeout_next = getattr(result_iterator, "next", None)

                if callable(timeout_next):
                    # Real multiprocessing IMapIterator supports timeout.
                    result = timeout_next(timeout=0.5)
                else:
                    # Unit tests may return a normal generator.
                    result = next(result_iterator)

            except multiprocessing.TimeoutError:
                progress_callback(
                    SearchPhaseEnum.BROAD_PHASE,
                    searches_complete,
                    search_count,
                    None,
                )

                if stop_event.is_set():
                    raise CancelException("Broadphase cancelled by user.") from None

                continue

            except StopIteration as err:
                raise BiggrepException("Broad-phase result iterator ended before all tasks completed.") from err

            (
                rule_name,
                search_id,
                index,
                search_string,
                returncode,
                stdout,
                stderr,
            ) = result

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

            current_percent = (searches_complete * 100) // search_count if search_count else 100

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

        duration = time.time() - start

        prom_bgparse_duration.labels(
            query_hash=query_hash,
        ).observe(duration)

        logger.debug(f"Total BigGrep parse time: {duration}")

    logger.debug("All index searches completed")
    rule_matches: RuleFileMatches = {}

    for rule_name, _plan in rule_search_plans.items():
        mode = broad_phase_modes[rule_name]
        result_sets = list(search_matches[rule_name].values())
        final_matches = set.union(*result_sets) if result_sets else set()

        if mode == "required_strings":
            logger.debug(
                'Rule "%s": %d combined required-string searches produced %d candidates',
                rule_name,
                len(result_sets),
                len(final_matches),
            )
        elif mode == "required_or_clause":
            logger.debug(
                'Rule "%s": selected required OR clause groups %s produced %d candidates',
                rule_name,
                selected_required_or_clauses[rule_name],
                len(final_matches),
            )
        elif mode == "required_groups":
            logger.debug(
                'Rule "%s": required_groups OR broad phase produced %d candidates',
                rule_name,
                len(final_matches),
            )
        else:
            logger.debug(
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
                content = 'import "pe"\n' + content
            compiled_yara_rules[rule_name] = yara.compile(source=content)

    # Bind metric children once instead of performing label lookups per file.
    missing_files_metric = prom_missing_files.labels(query_hash=query_hash)
    cpu_duration_metrics = {
        rule_name: prom_narrow_cpu_duration.labels(
            query_hash=query_hash,
            rule_name=rule_name,
        )
        for rule_name in rule_matches_sets
    }

    settings = RetrohuntSettings()
    chunk_size = settings.search_settings.chunk_size
    logger.debug("Narrow chunk size %d", chunk_size)
    # Split the files to process into smaller chunks
    chunks = chunk_dict(file_to_rules, chunk_size)

    # Worker function. Exceptions are intentionally allowed to propagate
    # through the thread pool result iterator, especially CancelException.
    def worker(file_path: str, rules_for_file: set[str]):
        if stop_event.is_set():
            raise CancelException("Narrow phase cancelled by user.")
        cfg = file_config.get(file_path)
        io_start = time.time()
        data = data_callback(file_path, cfg)
        io_duration = time.time() - io_start
        # Cancellation may have been requested while the dispatcher call was in progress.
        if stop_event.is_set():
            raise CancelException("Narrow phase cancelled by user.")
        data_len = 0
        if data:
            data_len = len(data)
        else:
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
        data = None
        return ("ok", file_path, rules_for_file, results, io_duration, data_len)

    def worker_task(task: tuple[str, set[str]]):
        file_path, rules_for_file = task
        return worker(file_path, rules_for_file)

    # Precompute progress totals.
    total_jobs = sum(len(paths) for paths in rule_matches_sets.values())
    jobs_complete = 0

    total_files = len(file_to_rules)
    files_complete = 0
    next_progress_percent = 5
    data_size_per_chunk = 0

    progress_callback(SearchPhaseEnum.NARROW_PHASE, 0, total_jobs, None)

    logger.info(
        "Narrow search starting: %d unique files to process across %d rule/file jobs",
        total_files,
        total_jobs,
    )
    processes = settings.search_settings.max_thread_count
    # Stream completed results from a fixed-size thread pool.
    # Number of threads used based on available memory in the container.
    logger.debug("Initiating narrow search with %d threads", processes)

    def process_chunk(chunk: dict[str, set[str]]) -> None:
        """Process exactly one chunk using one temporary thread pool."""
        nonlocal jobs_complete
        nonlocal total_jobs
        nonlocal files_complete
        nonlocal next_progress_percent
        nonlocal query_hash
        nonlocal data_size_per_chunk

        futures = {}

        with ThreadPoolExecutor(max_workers=processes) as executor:
            futures = {executor.submit(worker_task, item): item for item in chunk.items()}

            for future in as_completed(futures):
                try:
                    status, file_path, rules_for_file, results, io_duration, data_len = future.result()
                finally:
                    # Do not retain completed Future objects and their results.
                    futures.pop(future, None)

                prom_narrow_io_duration.labels(
                    query_hash=query_hash,
                ).observe(io_duration)

                prom_narrow_io_bytes.labels(
                    query_hash=query_hash,
                ).inc(data_len)

                if stop_event.is_set():
                    raise CancelException("Narrow phase cancelled by user.")

                data_size_per_chunk += data_len
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
                    continue

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

                # Explicitly release the current Future result.
                del results

    for chunk_number, chunk in enumerate(chunks, start=1):
        logger.debug(
            "Starting narrow-phase chunks %d containing %d files",
            chunk_number,
            len(chunk),
        )

        process_chunk(chunk)
        logger.info(f"Total size of data per chunk: {data_size_per_chunk / 1024 / 1024}")
        data_size_per_chunk = 0
        # process_chunk cannot return until ThreadPoolExecutor.__exit__ has run
        # and all worker threads from this chunk have terminated.
        del chunk

        logger.debug(
            "Narrow-phase chunk %d pool exited and memory cleanup completed",
            chunk_number,
        )

    # Convert back to lists and remove empty rules
    final_matches: RuleFileMatches = {}

    for rule_name, paths in rule_matches_sets.items():
        if paths:
            final_matches[rule_name] = list(paths)

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

    return final_matches


def trigger_stop_event():
    """Set stop event for threads if user cancels manually."""
    stop_event.set()


def clear_stop_event():
    """Clear the stop event flag."""
    stop_event.clear()


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
