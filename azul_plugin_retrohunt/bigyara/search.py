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
from .yara_parse import (
    AndNode,
    NOfNode,
    OrNode,
    RuleSearchPlans,
    StringNode,
    UnknownNode,
    parse_yara_rules,
)

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


# Boolean broad-phase expressions are safe upper approximations of the YARA
# condition. TRUE means "this subtree cannot safely restrict candidates".
# FALSE means the subtree cannot match. Stage nodes reference one searchable
# YARA string, where the string's alternative atom groups are OR-unioned.
_BOOL_TRUE = ("true",)
_BOOL_FALSE = ("false",)


def _make_bool_and(children):
    """Return a flattened and simplified boolean AND expression."""
    flattened = []

    for child in children:
        if child == _BOOL_FALSE:
            return _BOOL_FALSE
        if child == _BOOL_TRUE:
            continue
        if child[0] == "and":
            flattened.extend(child[1])
        else:
            flattened.append(child)

    unique_children = list(dict.fromkeys(flattened))
    if not unique_children:
        return _BOOL_TRUE
    if len(unique_children) == 1:
        return unique_children[0]
    return ("and", tuple(unique_children))


def _make_bool_or(children):
    """Return a flattened and simplified boolean OR expression."""
    flattened = []

    for child in children:
        if child == _BOOL_TRUE:
            return _BOOL_TRUE
        if child == _BOOL_FALSE:
            continue
        if child[0] == "or":
            flattened.extend(child[1])
        else:
            flattened.append(child)

    unique_children = list(dict.fromkeys(flattened))
    if not unique_children:
        return _BOOL_FALSE
    if len(unique_children) == 1:
        return unique_children[0]
    return ("or", tuple(unique_children))


def _make_bool_threshold(required: int, children):
    """Return a simplified at-least-N boolean expression."""
    if required <= 0:
        return _BOOL_TRUE

    true_children = 0
    remaining_children = []

    for child in children:
        if child == _BOOL_TRUE:
            true_children += 1
        elif child != _BOOL_FALSE:
            remaining_children.append(child)

    required -= true_children
    if required <= 0:
        return _BOOL_TRUE
    if required > len(remaining_children):
        return _BOOL_FALSE
    if required == 1:
        return _make_bool_or(remaining_children)
    if required == len(remaining_children):
        return _make_bool_and(remaining_children)

    # Do not deduplicate threshold children. Distinct YARA strings can have
    # identical atom searches and still count as separate N-of alternatives.
    return ("threshold", required, tuple(remaining_children))


def _register_string_stage(plan, string_name: str, stage_registry: dict):
    """Register one string's OR-of-atom-groups stage and return its key."""
    valid_group_ids = _valid_group_ids(
        plan,
        plan.string_groups.get(string_name, []),
    )
    if not valid_group_ids:
        return None

    alternatives_by_atoms = {}
    for group_idx in valid_group_ids:
        atoms = tuple(sorted(plan.groups[group_idx]))
        if atoms:
            alternatives_by_atoms.setdefault(atoms, group_idx)

    if not alternatives_by_atoms:
        return None

    alternatives = tuple(sorted(alternatives_by_atoms))
    stage_key = alternatives
    stage = stage_registry.get(stage_key)

    if stage is None:
        representative_group_ids = [alternatives_by_atoms[atoms] for atoms in alternatives]
        longest_atom = max(len(atom) for atoms in alternatives for atom in atoms)
        max_group_atom_count = max(len(atoms) for atoms in alternatives)

        stage = {
            "key": stage_key,
            "labels": set(),
            "group_ids": representative_group_ids,
            "alternatives": alternatives,
            "searches": [
                (
                    group_idx,
                    _bgparse_search_string(list(atoms)),
                )
                for group_idx, atoms in zip(
                    representative_group_ids,
                    alternatives,
                    strict=True,
                )
            ],
            "cost": len(alternatives),
            "longest_atom": longest_atom,
            "max_group_atom_count": max_group_atom_count,
        }
        stage_registry[stage_key] = stage

    stage["labels"].add(string_name)
    return stage_key


def _build_or_all_atoms_fallback_plan(plan):
    """Return a broad-phase plan that OR-searches every usable extracted atom.

    This is a compatibility fallback for valid YARA rules whose condition
    cannot be represented by the recursive broad-phase condition planner.
    Each unique atom is searched independently and all atom results are
    unioned. Narrow-phase YARA remains responsible for exact rule evaluation.
    """
    stage_registry = {}

    for string_name in sorted(plan.string_groups):
        for group_idx in _valid_group_ids(
            plan,
            plan.string_groups.get(string_name, []),
        ):
            for atom in plan.groups[group_idx]:
                stage_key = ((atom,),)
                stage = stage_registry.get(stage_key)

                if stage is None:
                    stage = {
                        "key": stage_key,
                        "labels": set(),
                        "group_ids": [group_idx],
                        "alternatives": ((atom,),),
                        "searches": [
                            (
                                group_idx,
                                _bgparse_search_string([atom]),
                            )
                        ],
                        "cost": 1,
                        "longest_atom": len(atom),
                        "max_group_atom_count": 1,
                    }
                    stage_registry[stage_key] = stage

                stage["labels"].add(string_name)

    if not stage_registry:
        return None

    stages = list(stage_registry.values())
    stages.sort(
        key=lambda stage: (
            -stage["longest_atom"],
            tuple(sorted(stage["labels"])),
            stage["key"],
        )
    )

    expression = _make_bool_or(("stage", stage["key"]) for stage in stages)

    return {
        "mode": "fallback_or_all_atoms",
        "expression": expression,
        "stages": stages,
        "stage_registry": stage_registry,
        "searches_per_index": len(stages),
        "pruned": False,
        "and_limit_events": [],
    }


def _build_searchable_boolean_expression(node, plan, stage_registry: dict):
    """Build a safe atom-search upper approximation of a condition AST.

    Unsupported predicates are represented as TRUE. This is deliberately
    conservative:

      unknown AND $a -> $a
      unknown OR  $a -> TRUE (no safe atom-only restriction)

    Therefore the returned expression can only contain the same files or more
    files than the real YARA condition.
    """
    if node is None:
        return _BOOL_TRUE

    if isinstance(node, UnknownNode):
        raw_text = (node.raw_text or "").strip().lower()
        if raw_text == "false":
            return _BOOL_FALSE
        return _BOOL_TRUE

    if isinstance(node, StringNode):
        stage_key = _register_string_stage(
            plan,
            node.string_name,
            stage_registry,
        )
        if stage_key is None:
            return _BOOL_TRUE
        return ("stage", stage_key)

    if isinstance(node, AndNode):
        return _make_bool_and(
            _build_searchable_boolean_expression(
                child,
                plan,
                stage_registry,
            )
            for child in node.children
        )

    if isinstance(node, OrNode):
        return _make_bool_or(
            _build_searchable_boolean_expression(
                child,
                plan,
                stage_registry,
            )
            for child in node.children
        )

    if isinstance(node, NOfNode):
        return _make_bool_threshold(
            node.required,
            [
                _build_searchable_boolean_expression(
                    child,
                    plan,
                    stage_registry,
                )
                for child in node.children
            ],
        )

    # A new parser node must never accidentally become a restrictive filter.
    return _BOOL_TRUE


def _expression_stage_keys(expression) -> set:
    """Return all stage keys referenced by a boolean expression."""
    operator = expression[0]

    if operator == "stage":
        return {expression[1]}
    if operator in {"true", "false"}:
        return set()
    if operator in {"and", "or"}:
        children = expression[1]
    elif operator == "threshold":
        children = expression[2]
    else:
        raise ValueError(f"Unknown boolean broad-phase operator: {operator}")

    stage_keys = set()
    for child in children:
        stage_keys.update(_expression_stage_keys(child))
    return stage_keys


def _restrict_expression_to_stages(expression, selected_stage_keys: set):
    """Replace unselected stages with TRUE and simplify safely."""
    operator = expression[0]

    if operator == "stage":
        if expression[1] in selected_stage_keys:
            return expression
        return _BOOL_TRUE
    if operator in {"true", "false"}:
        return expression
    if operator == "and":
        return _make_bool_and(_restrict_expression_to_stages(child, selected_stage_keys) for child in expression[1])
    if operator == "or":
        return _make_bool_or(_restrict_expression_to_stages(child, selected_stage_keys) for child in expression[1])
    if operator == "threshold":
        return _make_bool_threshold(
            expression[1],
            [
                _restrict_expression_to_stages(
                    child,
                    selected_stage_keys,
                )
                for child in expression[2]
            ],
        )

    raise ValueError(f"Unknown boolean broad-phase operator: {operator}")


def _stage_set_cost(stage_keys: set, stage_registry: dict) -> int:
    """Return searches-per-index needed for a set of stages."""
    return sum(stage_registry[stage_key]["cost"] for stage_key in stage_keys)


def _minimum_restrictive_stage_set(expression, stage_registry: dict):
    """Return a low-cost stage set that keeps expression non-TRUE.

    This is used only when the complete condition exceeds configured broad
    search limits. Replacing every omitted stage with TRUE broadens the
    condition, so any returned subset remains safe.
    """
    operator = expression[0]

    if operator == "true":
        return None
    if operator == "false":
        return set()
    if operator == "stage":
        return {expression[1]}

    if operator == "and":
        candidates = [_minimum_restrictive_stage_set(child, stage_registry) for child in expression[1]]
        candidates = [candidate for candidate in candidates if candidate is not None]
        if not candidates:
            return None
        return min(
            candidates,
            key=lambda candidate: (
                _stage_set_cost(candidate, stage_registry),
                len(candidate),
                repr(sorted(candidate, key=repr)),
            ),
        )

    if operator == "or":
        selected = set()
        for child in expression[1]:
            child_selection = _minimum_restrictive_stage_set(
                child,
                stage_registry,
            )
            if child_selection is None:
                return None
            selected.update(child_selection)
        return selected

    if operator == "threshold":
        required = expression[1]
        children = expression[2]

        # If U children are replaced by TRUE, the threshold becomes
        # nonrestrictive when U >= required. Therefore at least
        # len(children) - required + 1 children must remain restrictive.
        children_needed = len(children) - required + 1
        child_options = []

        for child in children:
            child_selection = _minimum_restrictive_stage_set(
                child,
                stage_registry,
            )
            if child_selection is not None:
                child_options.append(child_selection)

        if len(child_options) < children_needed:
            return None

        selected = set()
        remaining_options = list(child_options)

        for _ in range(children_needed):
            best_option = min(
                remaining_options,
                key=lambda option: (
                    _stage_set_cost(option - selected, stage_registry),
                    _stage_set_cost(option, stage_registry),
                    len(option),
                    repr(sorted(option, key=repr)),
                ),
            )
            selected.update(best_option)
            remaining_options.remove(best_option)

        return selected

    raise ValueError(f"Unknown boolean broad-phase operator: {operator}")


def _collect_activation_bundles(expression, stage_registry: dict) -> list[set]:
    """Return useful stage bundles for progressively strengthening a plan."""
    bundles = []
    seen = set()

    def visit(node):
        minimum = _minimum_restrictive_stage_set(node, stage_registry)
        if minimum:
            frozen = frozenset(minimum)
            if frozen not in seen:
                seen.add(frozen)
                bundles.append(set(minimum))

        operator = node[0]
        if operator in {"and", "or"}:
            for child in node[1]:
                visit(child)
        elif operator == "threshold":
            for child in node[2]:
                visit(child)

    visit(expression)
    return bundles


def _stage_strength(stage: dict) -> tuple:
    """Return a deterministic approximation of atom selectivity."""
    return (
        stage["longest_atom"],
        stage["max_group_atom_count"],
        -stage["cost"],
        tuple(sorted(stage["labels"])),
    )


def _and_child_strength(expression, stage_registry: dict) -> tuple:
    """Estimate which AND operand is most useful to retain.

    This affects only which safe conjuncts are selected when an AND node
    exceeds its configured operand limit. It cannot affect correctness:
    omitted operands are replaced with TRUE, which only broadens candidates.
    """
    operator = expression[0]
    stage_keys = _expression_stage_keys(expression)
    total_cost = _stage_set_cost(stage_keys, stage_registry)

    if operator == "stage":
        stage = stage_registry[expression[1]]
        return (
            stage["longest_atom"],
            stage["max_group_atom_count"],
            -total_cost,
            -1,
            0,
        )

    if operator in {"true", "false"}:
        return (0, 0, 0, 0, 0)

    if operator in {"and", "or"}:
        children = expression[1]
    elif operator == "threshold":
        children = expression[2]
    else:
        raise ValueError(f"Unknown boolean broad-phase operator: {operator}")

    child_scores = [_and_child_strength(child, stage_registry) for child in children]
    if not child_scores:
        return (0, 0, -total_cost, -len(stage_keys), 0)

    if operator == "or":
        # An OR is only as selective as its broadest-looking alternative.
        representative = min(child_scores)
    elif operator == "threshold":
        # For N-of, use the Nth strongest child as a conservative proxy for
        # the selectivity gained by retaining the complete threshold operand.
        required = max(1, min(expression[1], len(child_scores)))
        representative = sorted(child_scores, reverse=True)[required - 1]
    else:
        # Nested ANDs are normally flattened, but use the strongest child if
        # one remains inside another expression type.
        representative = max(child_scores)

    return (
        representative[0],
        representative[1],
        -total_cost,
        -len(stage_keys),
        -len(children),
    )


def _limit_boolean_and_children(
    expression,
    stage_registry: dict,
    max_and_children: int,
):
    """Limit every Boolean AND node to its strongest safe operands.

    Every omitted operand is replaced with TRUE. For an original expression:

        A AND B AND C AND D AND E

    retaining only A, B, C, and D produces a superset of the original matches.
    This can increase narrow-phase candidates, but cannot exclude a real YARA
    match. OR and threshold breadth are not capped by this setting.
    """
    limit_events = []

    def visit(node):
        operator = node[0]

        if operator in {"true", "false", "stage"}:
            return node

        if operator == "or":
            return _make_bool_or(visit(child) for child in node[1])

        if operator == "threshold":
            return _make_bool_threshold(
                node[1],
                [visit(child) for child in node[2]],
            )

        if operator != "and":
            raise ValueError(f"Unknown boolean broad-phase operator: {operator}")

        simplified = _make_bool_and(visit(child) for child in node[1])
        if simplified[0] != "and":
            return simplified

        children = list(simplified[1])
        if len(children) <= max_and_children:
            return simplified

        ranked_children = sorted(
            children,
            key=lambda child: (
                _and_child_strength(child, stage_registry),
                repr(child),
            ),
            reverse=True,
        )
        selected_set = set(ranked_children[:max_and_children])
        kept_children = [child for child in children if child in selected_set]
        omitted_children = [child for child in children if child not in selected_set]

        limit_events.append(
            {
                "original_count": len(children),
                "kept_count": len(kept_children),
                "kept": tuple(kept_children),
                "omitted": tuple(omitted_children),
            }
        )
        return _make_bool_and(kept_children)

    return visit(expression), limit_events


def _choose_boolean_stages(
    expression,
    stage_registry: dict,
    preferred_searches_per_index: int,
    hard_searches_per_index: int,
):
    """Select as much of a safe boolean expression as configured limits allow."""
    all_stage_keys = _expression_stage_keys(expression)
    full_cost = _stage_set_cost(all_stage_keys, stage_registry)

    if full_cost <= preferred_searches_per_index and full_cost <= hard_searches_per_index:
        return expression, all_stage_keys, full_cost, False

    minimum_selection = _minimum_restrictive_stage_set(
        expression,
        stage_registry,
    )
    if minimum_selection is None:
        return _BOOL_TRUE, set(), 0, False

    minimum_cost = _stage_set_cost(minimum_selection, stage_registry)
    if minimum_cost > hard_searches_per_index:
        raise BiggrepException(
            "The smallest safe boolean broad-phase plan needs "
            f"{minimum_cost} searches per index, but the global task limit "
            f"allows only {hard_searches_per_index} searches per index."
        )

    # The per-index setting is a preferred cap. As with the previous mandatory
    # string implementation, exceed it only when that is required to retain one
    # safe filter. The global task limit remains hard.
    target_budget = min(
        hard_searches_per_index,
        max(preferred_searches_per_index, minimum_cost),
    )

    selected = set(minimum_selection)
    current_expression = _restrict_expression_to_stages(
        expression,
        selected,
    )

    bundles = _collect_activation_bundles(expression, stage_registry)
    bundles.extend({stage_key} for stage_key in all_stage_keys)

    while True:
        best = None

        for bundle in bundles:
            candidate_keys = selected | bundle
            if candidate_keys == selected:
                continue

            candidate_cost = _stage_set_cost(
                candidate_keys,
                stage_registry,
            )
            if candidate_cost > target_budget:
                continue

            candidate_expression = _restrict_expression_to_stages(
                expression,
                candidate_keys,
            )
            if candidate_expression == current_expression:
                continue

            added_keys = candidate_keys - selected
            aggregate_strength = tuple(
                sum(_stage_strength(stage_registry[key])[index] for key in added_keys) for index in range(3)
            )
            score = (
                aggregate_strength,
                len(added_keys),
                -_stage_set_cost(added_keys, stage_registry),
                repr(candidate_expression),
            )

            if best is None or score > best[0]:
                best = (
                    score,
                    candidate_keys,
                    candidate_expression,
                )

        if best is None:
            break

        _score, selected, current_expression = best

        # Remove any selected stages simplified out of the expression so their
        # task budget can be reused by another useful structure.
        selected = _expression_stage_keys(current_expression)

    selected_cost = _stage_set_cost(selected, stage_registry)
    return current_expression, selected, selected_cost, selected != all_stage_keys


def _format_boolean_expression(expression, stage_registry: dict) -> str:
    """Return a readable description of a boolean broad-phase expression."""
    operator = expression[0]
    logger.info("non readable expression: ", expression)
    logger.info("stage registry ", stage_registry)
    if operator == "true":
        return "TRUE (no safe atom restriction)"
    if operator == "false":
        return "FALSE"
    if operator == "stage":
        labels = sorted(stage_registry[expression[1]]["labels"])
        return "/".join(labels)
    if operator == "and":
        return "(" + " AND ".join(_format_boolean_expression(child, stage_registry) for child in expression[1]) + ")"
    if operator == "or":
        return "(" + " OR ".join(_format_boolean_expression(child, stage_registry) for child in expression[1]) + ")"
    if operator == "threshold":
        children = ", ".join(_format_boolean_expression(child, stage_registry) for child in expression[2])
        return f"AT_LEAST_{expression[1]}({children})"

    raise ValueError(f"Unknown boolean broad-phase operator: {operator}")


def _evaluate_boolean_expression(expression, stage_matches: dict) -> set[str]:
    """Evaluate a planned boolean expression over broad-phase candidate sets."""
    operator = expression[0]

    if operator == "false":
        return set()
    if operator == "true":
        raise BiggrepException("Attempted to evaluate a nonrestrictive TRUE broad-phase plan.")
    if operator == "stage":
        return set(stage_matches.get(expression[1], set()))

    if operator == "and":
        child_results = [_evaluate_boolean_expression(child, stage_matches) for child in expression[1]]
        if not child_results:
            raise BiggrepException("Boolean AND plan contained no children.")

        child_results.sort(key=len)
        result = child_results[0]
        for child_result in child_results[1:]:
            result.intersection_update(child_result)
            if not result:
                break
        logger.info("Result: ", result)
        return result

    if operator == "or":
        result = set()
        for child in expression[1]:
            result.update(
                _evaluate_boolean_expression(
                    child,
                    stage_matches,
                )
            )
        logger.info("Result: ", result)
        return result

    if operator == "threshold":
        required = expression[1]
        counts: dict[str, int] = {}

        for child in expression[2]:
            for path in _evaluate_boolean_expression(child, stage_matches):
                counts[path] = counts.get(path, 0) + 1
        logger.info("Result: ", {path for path, count in counts.items() if count >= required})
        return {path for path, count in counts.items() if count >= required}

    raise ValueError(f"Unknown boolean broad-phase operator: {operator}")


def _build_rule_boolean_plan(
    rule_name: str,
    plan,
    max_required_strings: int,
    preferred_searches_per_index: int,
    hard_searches_per_index: int,
):
    """Build the strongest safe boolean broad-phase plan within limits.

    max_required_strings retains its existing public/configuration name for
    compatibility. In the recursive planner it is also the maximum number of
    operands retained at every AND node.
    """
    stage_registry = {}
    condition_ast = getattr(plan, "condition_ast", None)
    expression = _build_searchable_boolean_expression(
        condition_ast,
        plan,
        stage_registry,
    )
    print("THIS IS EXPRESSION: ", expression)
    mode = "boolean_expression"

    # If YARA atom extraction succeeded but our condition planner could not
    # derive any restrictive expression, fall back to OR-searching every
    # usable extracted atom. Narrow-phase YARA still decides exact matches.
    if expression == _BOOL_TRUE:
        return _build_or_all_atoms_fallback_plan(plan)

    expression, and_limit_events = _limit_boolean_and_children(
        expression,
        stage_registry,
        max_required_strings,
    )

    if expression == _BOOL_TRUE:
        return None

    if expression == _BOOL_FALSE:
        return {
            "mode": mode,
            "expression": expression,
            "stages": [],
            "stage_registry": stage_registry,
            "searches_per_index": 0,
            "pruned": False,
            "and_limit_events": and_limit_events,
        }

    (
        selected_expression,
        selected_stage_keys,
        selected_searches_per_index,
        pruned,
    ) = _choose_boolean_stages(
        expression,
        stage_registry,
        preferred_searches_per_index,
        hard_searches_per_index,
    )

    if selected_expression == _BOOL_TRUE:
        return _build_or_all_atoms_fallback_plan(plan)

    stages = [stage_registry[stage_key] for stage_key in selected_stage_keys]
    stages.sort(
        key=lambda stage: (
            -stage["longest_atom"],
            -stage["max_group_atom_count"],
            stage["cost"],
            tuple(sorted(stage["labels"])),
        )
    )

    return {
        "mode": mode,
        "expression": selected_expression,
        "stages": stages,
        "stage_registry": stage_registry,
        "searches_per_index": selected_searches_per_index,
        "pruned": pruned,
        "and_limit_events": and_limit_events,
    }


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
    """Search every safely representable condition structure in broad phase.

    Each YARA string is represented as an OR-union of its alternative atom
    groups. The condition AST is then evaluated recursively with AND, OR, and
    at-least-N set operations. Unsupported predicates are treated as TRUE,
    which can only broaden candidates.

    If an unsupported or unsearchable OR branch could satisfy the rule by
    itself, no atom-only filter is safe and the planner refuses to run rather
    than silently omit real matches.
    """
    if query_type == QueryTypeEnum.SURICATA:
        raise NotImplementedError("Suricata broad-phase search is not implemented yet.")

    bgparse_exec = executables["bgparse"]
    logger.debug("Rule search plans broad phase: %s", rule_search_plans)

    settings = RetrohuntSettings().search_settings
    logger.warning(
        "Search settings types: "
        "max_required_strings_per_and_search=%r (%s), "
        "max_required_string_searches_per_index=%r (%s), "
        "max_required_broad_phase_workers=%r (%s), "
        "max_broad_phase_tasks=%r (%s), "
        "max_thread_count=%r (%s), "
        "max_narrow_phase_inflight_files=%r (%s), "
        "default_narrow_phase_cleanup_multiplier=%r (%s)",
        settings.max_required_strings_per_and_search,
        type(settings.max_required_strings_per_and_search).__name__,
        settings.max_required_string_searches_per_index,
        type(settings.max_required_string_searches_per_index).__name__,
        settings.max_required_broad_phase_workers,
        type(settings.max_required_broad_phase_workers).__name__,
        settings.max_broad_phase_tasks,
        type(settings.max_broad_phase_tasks).__name__,
        settings.max_thread_count,
        type(settings.max_thread_count).__name__,
        settings.max_narrow_phase_inflight_files,
        type(settings.max_narrow_phase_inflight_files).__name__,
        settings.default_narrow_phase_cleanup_multiplier,
        type(settings.default_narrow_phase_cleanup_multiplier).__name__,
    )

    max_and_children = settings.max_required_strings_per_and_search
    preferred_searches_per_index = settings.max_required_string_searches_per_index
    broad_phase_workers = settings.max_required_broad_phase_workers
    max_broad_phase_tasks = settings.max_broad_phase_tasks

    # max_and_children = _positive_int_setting(
    #    settings,
    #    "max_required_strings_per_and_search",
    #    _DEFAULT_MAX_REQUIRED_STRINGS_PER_AND_SEARCH,
    # )
    # preferred_searches_per_index = _positive_int_setting(
    #    settings,
    #    "max_required_string_searches_per_index",
    #    _DEFAULT_MAX_REQUIRED_STRING_SEARCHES_PER_INDEX,
    # )
    # configured_broad_workers = _positive_int_setting(
    #    settings,
    #    "max_broad_phase_workers",
    #    _DEFAULT_MAX_BROAD_PHASE_WORKERS,
    # )
    # max_broad_phase_tasks = _positive_int_setting(
    #    settings,
    #    "max_broad_phase_tasks",
    #    _DEFAULT_MAX_BROAD_PHASE_TASKS,
    # )
    # broad_phase_workers = min(
    #    configured_broad_workers,
    #    os.cpu_count() or 1,
    # )

    if len(indices) > max_broad_phase_tasks:
        raise BiggrepException(
            f"{len(indices)} indexes already exceed max_broad_phase_tasks="
            f"{max_broad_phase_tasks}; even one search per index is impossible."
        )

    hard_searches_per_index = max_broad_phase_tasks // len(indices)
    broad_plans: dict[str, dict] = {}

    for rule_name, plan in rule_search_plans.items():
        rule_plan = _build_rule_boolean_plan(
            rule_name,
            plan,
            max_and_children,
            preferred_searches_per_index,
            hard_searches_per_index,
        )

        if rule_plan is None:
            raise NoAtomException(f'Rule "{rule_name}" has no usable extracted atoms for broad-phase fallback.')

        broad_plans[rule_name] = rule_plan

        if rule_plan["mode"] == "fallback_or_all_atoms":
            logger.warning(
                'Rule "%s": the YARA rule produced valid atoms, but its '
                "condition could not be represented safely by the broad-phase "
                "planner. Falling back to OR-searching all %d unique extracted "
                "atoms; narrow-phase YARA will evaluate the original condition.",
                rule_name,
                len(rule_plan["stages"]),
            )

        expression_text = _format_boolean_expression(
            rule_plan["expression"],
            rule_plan["stage_registry"],
        )
        logger.info(
            'Rule "%s": broad phase will evaluate %s using %d unique '
            "string stages and %d atom-group searches per index.",
            rule_name,
            expression_text,
            len(rule_plan["stages"]),
            rule_plan["searches_per_index"],
        )

        for and_number, limit_event in enumerate(
            rule_plan["and_limit_events"],
            start=1,
        ):
            kept_text = " AND ".join(
                _format_boolean_expression(
                    child,
                    rule_plan["stage_registry"],
                )
                for child in limit_event["kept"]
            )
            logger.warning(
                'Rule "%s": AND node %d contained %d operands; retained the '
                "strongest %d because max_required_strings_per_and_search=%d. "
                "Kept: %s. The other %d operands were replaced with TRUE, "
                "which can only add narrow-phase candidates.",
                rule_name,
                and_number,
                limit_event["original_count"],
                limit_event["kept_count"],
                max_and_children,
                kept_text,
                len(limit_event["omitted"]),
            )

        if rule_plan["pruned"]:
            logger.warning(
                'Rule "%s": the complete safe boolean plan exceeded configured '
                "search limits. Omitted stages were replaced with TRUE, which "
                "can only add narrow-phase candidates. Active plan: %s",
                rule_name,
                expression_text,
            )

        for stage_number, stage in enumerate(rule_plan["stages"], start=1):
            logger.info(
                'Rule "%s": boolean stage %d/%d represents %s with %d alternative atom-group searches: %s',
                rule_name,
                stage_number,
                len(rule_plan["stages"]),
                "/".join(sorted(stage["labels"])),
                stage["cost"],
                "; ".join("[" + ", ".join(repr(atom) for atom in atoms) + "]" for atoms in stage["alternatives"]),
            )

    searches_per_index = sum(rule_plan["searches_per_index"] for rule_plan in broad_plans.values())
    search_count = len(indices) * searches_per_index

    if search_count > max_broad_phase_tasks:
        raise BiggrepException(
            f"Broad-phase plan would generate {search_count} tasks across "
            f"{len(indices)} indexes, exceeding max_broad_phase_tasks="
            f"{max_broad_phase_tasks}. Reduce the number of rules or increase "
            "the task limit. The planner will not use an unsafe fallback."
        )

    if search_count == 0:
        if any(rule_plan["expression"] != _BOOL_FALSE for rule_plan in broad_plans.values()):
            if query_type == QueryTypeEnum.STRING:
                raise NoIndexMatchesException("Search aborted due to no index matches.")
            raise NoAtomException("Broad-phase planner generated no usable atom searches.")

        raise NoIndexMatchesException("All rule conditions reduced to FALSE.")

    logger.info(
        "Broad search starting: %d tasks across %d indexes using up to %d workers",
        search_count,
        len(indices),
        broad_phase_workers,
    )

    searches_complete = 0
    next_progress_percent = 20
    progress_callback(
        SearchPhaseEnum.BROAD_PHASE,
        0,
        search_count,
        None,
    )

    file_config: FileConfig = {}
    rule_matches: RuleFileMatches = {}
    start_time = time.time()

    for rule_name, rule_plan in broad_plans.items():
        stage_matches_by_key: dict[tuple, set[str]] = {}
        rule_config: FileConfig = {}

        for stage_number, stage in enumerate(
            rule_plan["stages"],
            start=1,
        ):
            stage_task_count = len(indices) * len(stage["searches"])
            stage_matches: set[str] = set()

            def iter_stage_tasks(
                stage_searches=stage["searches"],
                rule_name=rule_name,
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
                            True,
                            None,
                        )

            task_iterator = iter(iter_stage_tasks())
            pending = {}

            with ThreadPoolExecutor(max_workers=broad_phase_workers) as executor:
                for _ in range(min(broad_phase_workers, stage_task_count)):
                    try:
                        task = next(task_iterator)
                    except StopIteration:
                        break
                    pending[
                        executor.submit(
                            _run_bgparse_task_args,
                            task,
                        )
                    ] = task

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
                            error_message = error_text.split(
                                "<error>",
                                1,
                            )[1]
                            if ":" in error_message:
                                error_message = error_message.split(
                                    ":",
                                    1,
                                )[1]
                            error_message = error_message.split(
                                "\n",
                                1,
                            )[0]
                            raise BiggrepException(
                                f"bgparse error:{error_message} - errored "
                                f"while searching for {completed_rule_name} "
                                f"in {index}"
                            )

                        stage_matches.update(new_matches)

                        for path, cfg in task_config.items():
                            rule_config.setdefault(path, cfg)

                        stage_complete += 1
                        searches_complete += 1

                        progress_callback(
                            SearchPhaseEnum.BROAD_PHASE,
                            searches_complete,
                            search_count,
                            (
                                completed_rule_name,
                                new_matches,
                            ),
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
                            pending[
                                executor.submit(
                                    _run_bgparse_task_args,
                                    task,
                                )
                            ] = task

                        del new_matches
                        del task_config
                        del stderr

            if stage_complete != stage_task_count:
                raise BiggrepException(
                    f"Broad-phase stage completed {stage_complete} of {stage_task_count} expected tasks."
                )

            stage_matches_by_key[stage["key"]] = stage_matches

            logger.info(
                'Rule "%s": boolean stage %d/%d (%s) produced %d candidates.',
                rule_name,
                stage_number,
                len(rule_plan["stages"]),
                "/".join(sorted(stage["labels"])),
                len(stage_matches),
            )

            del pending
            del task_iterator
            release_unused_memory()

        final_candidates = _evaluate_boolean_expression(
            rule_plan["expression"],
            stage_matches_by_key,
        )
        rule_matches[rule_name] = list(final_candidates)

        for path in final_candidates:
            cfg = rule_config.get(path)
            if cfg is not None:
                file_config[path] = cfg

        logger.info(
            'Rule "%s": final boolean broad-phase evaluation returned %d candidates for narrow phase.',
            rule_name,
            len(final_candidates),
        )

        stage_matches_by_key.clear()
        rule_config.clear()
        release_unused_memory()

    duration = time.time() - start_time
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

    total_files = len(file_to_rules)
    settings = RetrohuntSettings().search_settings
    logger.warning(
        "Search settings types: "
        "max_required_strings_per_and_search=%r (%s), "
        "max_required_string_searches_per_index=%r (%s), "
        "max_required_broad_phase_workers=%r (%s), "
        "max_broad_phase_tasks=%r (%s), "
        "max_thread_count=%r (%s), "
        "max_narrow_phase_inflight_files=%r (%s), "
        "default_narrow_phase_cleanup_multiplier=%r (%s)",
        settings.max_required_strings_per_and_search,
        type(settings.max_required_strings_per_and_search).__name__,
        settings.max_required_string_searches_per_index,
        type(settings.max_required_string_searches_per_index).__name__,
        settings.max_required_broad_phase_workers,
        type(settings.max_required_broad_phase_workers).__name__,
        settings.max_broad_phase_tasks,
        type(settings.max_broad_phase_tasks).__name__,
        settings.max_thread_count,
        type(settings.max_thread_count).__name__,
        settings.max_narrow_phase_inflight_files,
        type(settings.max_narrow_phase_inflight_files).__name__,
        settings.default_narrow_phase_cleanup_multiplier,
        type(settings.default_narrow_phase_cleanup_multiplier).__name__,
    )
    configured_threads = settings.max_thread_count
    # max_inflight_files = settings.max_narrow_phase_inflight_files
    active_workers = min(configured_threads, total_files)
    cleanup_batch_size = active_workers * settings.default_narrow_phase_cleanup_multiplier

    print("configured threads: ", configured_threads)
    print("active workers: ", active_workers)
    print(" cleanup batch size: ", cleanup_batch_size)
    # configured_threads = _positive_int_setting(
    #    search_settings,
    #    "max_thread_count",
    #    1,
    # )
    # default_inflight_files = min(
    #    configured_threads,
    #    _DEFAULT_MAX_NARROW_PHASE_INFLIGHT_FILES,
    # )
    # max_inflight_files = _positive_int_setting(
    #    search_settings,
    #    "max_narrow_phase_inflight_files",
    #    default_inflight_files,
    # )

    # active_workers = max(
    #    1,
    #    min(configured_threads, max_inflight_files, total_files or 1),
    # )
    # cleanup_batch_size = _positive_int_setting(
    #    search_settings,
    #    "narrow_phase_cleanup_batch_size",
    #    active_workers * _DEFAULT_NARROW_PHASE_CLEANUP_MULTIPLIER,
    # )
    # cleanup_batch_size = max(active_workers, cleanup_batch_size)

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
