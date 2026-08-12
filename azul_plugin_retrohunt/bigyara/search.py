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
    """Run the explicit memory-reclamation step used between bounded search phases.

    The function first runs Python's cyclic garbage collector so unreachable
    container objects, Futures, tracebacks, and other cyclic references can be
    released.  On glibc-based Linux systems it then calls malloc_trim(0), when
    available, to ask the native allocator to return completely free heap pages to
    the operating system.

    This is used after broad-phase stages, narrow-phase cleanup batches, and other
    large temporary allocations have been released.  Python garbage collection
    alone does not guarantee that native YARA buffers or freed malloc arenas reduce
    the process RSS, so the optional malloc_trim call is important for keeping
    long-running Retrohunt workers within their container memory budget.

    malloc_trim is best-effort only.  Failure to load or invoke it must never make
    a hunt fail, so unsupported platforms simply perform garbage collection and
    continue.
    """
    gc.collect()

    if _malloc_trim is not None:
        try:
            _malloc_trim(0)
        except (OSError, ValueError):
            logger.debug("malloc_trim failed", exc_info=True)


def _current_rss_mib() -> float | None:
    """Return the current process resident-set size in MiB when running on Linux.

    The function reads /proc/self/statm, extracts the resident page count, and
    multiplies it by the operating-system page size before converting the value to
    MiB.  The result represents memory currently resident for this Retrohunt
    process and is used only for operational logging around narrow-phase cleanup.

    If /proc is unavailable, malformed, or unsupported, the function returns None
    instead of raising.  Memory telemetry must never affect search correctness or
    cause a hunt to fail.
    """
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
    """Build the bgparse command-line search arguments for one mandatory atom group.

    Each byte string is converted to uppercase hexadecimal and emitted as a
    separate ``-s<HEX>`` argument.  Duplicate atoms are removed while preserving
    their original order.  Multiple ``-s`` arguments in a single bgparse command
    have AND semantics, so every returned atom must be present for that physical
    search to match an indexed file.

    This helper is therefore used only when the caller has already determined that
    the supplied atoms belong to the same mandatory atom group, or when several
    single-search YARA strings are being safely batched as a direct Boolean AND.
    It must not be used to represent OR alternatives.
    """
    unique_atoms = dict.fromkeys(atoms)
    return "".join(f"-s{binascii.b2a_hex(atom).upper().decode()} " for atom in unique_atoms)


def _valid_group_ids(plan, group_ids) -> list[int]:
    """Return the usable atom-group identifiers referenced by a parsed YARA plan.

    The parser stores atom groups by numeric index and each YARA string references
    one or more of those indexes.  This helper filters out negative indexes,
    indexes beyond the end of ``plan.groups``, and groups that contain no atoms.
    It also removes duplicate group IDs while preserving their first-seen order.

    Centralising this validation prevents malformed or empty groups from becoming
    bgparse tasks and gives the Boolean planner a consistent definition of a
    searchable physical atom group.
    """
    return list(
        dict.fromkeys(
            group_idx for group_idx in group_ids if 0 <= group_idx < len(plan.groups) and plan.groups[group_idx]
        )
    )


# Boolean broad-phase expressions are safe upper approximations of the YARA
# condition. TRUE means "this subtree cannot safely restrict candidates".
# FALSE means the subtree cannot match. Stage nodes reference one searchable
# YARA string, where the string's alternative atom groups are OR-unioned.
_BOOL_TRUE = ("true",)
_BOOL_FALSE = ("false",)


def _make_bool_and(children):
    """Construct a canonical Boolean AND node while applying safe simplifications.

    Children are consumed in order.  FALSE short-circuits the entire expression to
    FALSE, TRUE children are discarded because they do not restrict an AND, and
    nested AND nodes are flattened into the parent.  Duplicate child expressions
    are then removed.  An empty result becomes TRUE, a single remaining child is
    returned directly, and two or more children become ``("and", children)``.

    The planner uses this normalisation whenever it creates or rewrites an AND
    subtree.  Keeping the representation flat and simplified reduces later stage
    selection work while preserving the conservative broad-phase semantics.
    """
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
    """Construct a canonical Boolean OR node while applying safe simplifications.

    TRUE short-circuits the entire OR to TRUE because an unrestricted branch can
    satisfy the broad approximation.  FALSE children are discarded, nested OR
    nodes are flattened, and duplicate child expressions are removed.  An empty
    OR becomes FALSE, one remaining child is returned directly, and multiple
    children become ``("or", children)``.

    This normalisation is important because OR is the dangerous operator for a
    conservative broad-phase approximation: if any branch becomes TRUE, no
    atom-only restriction is safe for that OR subtree.
    """
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
    """Construct and simplify an at-least-N Boolean threshold expression.

    TRUE children count as already-satisfied votes and reduce the remaining
    required count.  FALSE children cannot contribute and are discarded.  The
    function then collapses trivial cases: zero required votes becomes TRUE,
    an impossible threshold becomes FALSE, one required vote becomes OR, and
    requiring every remaining child becomes AND.  Otherwise a
    ``("threshold", required, children)`` node is returned.

    Threshold children are intentionally not deduplicated.  Two distinct YARA
    identifiers can resolve to the same physical atom search while still counting
    as two separate votes under YARA N-of semantics.  Preserving those semantic
    votes is required to avoid changing the rule.
    """
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
    """Register the physical broad-phase representation of one YARA string.

    A YARA string can have one or more usable atom groups.  Each atom group is one
    physical bgparse AND search, while multiple groups for the same YARA string
    are alternatives and therefore OR together.  This function validates the
    string's referenced groups, canonicalises each group by sorting its atoms,
    deduplicates identical alternatives, and uses the resulting tuple of
    alternatives as the stage key.

    Stages with identical physical searches are shared in ``stage_registry`` even
    when they originate from different YARA identifiers.  The stage records the
    representative group IDs, generated bgparse command strings, physical search
    cost, selectivity hints, and all YARA labels represented by that search.

    The returned key is used by the Boolean expression tree.  Returning None means
    the string has no usable atom group and therefore cannot safely restrict the
    broad phase on its own.
    """
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


def _stage_label_text(stage: dict) -> str:
    """Return a human-readable YARA label description for a physical search stage.

    Ordinary stages may represent one or more YARA labels that share the same
    physical atom searches, so their labels are rendered with ``/`` separators.
    A combined direct-AND stage preserves its constituent label groups and renders
    them with ``AND`` separators so logs clearly show that multiple mandatory YARA
    strings were executed in one bgparse command.

    This helper affects logging only; it does not alter stage identity, execution,
    or Boolean evaluation.
    """
    if stage.get("combined_and"):
        return " AND ".join("/".join(label_group) for label_group in stage["label_groups"])

    return "/".join(sorted(stage["labels"]))


def _build_or_all_atoms_fallback_plan(plan):
    """Build the conservative compatibility fallback that OR-searches every usable atom.

    This path is used when YARA parsing extracted valid atoms but the recursive
    condition planner cannot derive a restrictive atom-only Boolean expression.
    Every unique atom from every usable string group becomes its own one-search
    stage, and all of those stages are joined by OR.

    The fallback deliberately ignores the original Boolean relationship between
    those atoms.  That can produce many extra broad-phase candidates, but any file
    containing a usable extracted atom remains eligible for narrow-phase YARA,
    which evaluates the original rule exactly.  The fallback is therefore a
    compatibility mechanism intended to avoid rejecting otherwise valid rules when
    their condition syntax is not representable by the broad planner.

    If no usable atoms exist at all, None is returned and the caller must fail
    rather than pretending that a meaningful broad search can be performed.
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
    """Translate the parsed YARA condition AST into a safe atom-search expression.

    StringNode objects are registered as physical stages.  AndNode, OrNode, and
    NOfNode objects are recursively converted to the planner's AND, OR, and
    threshold tuples using the normalising helpers.  Unsupported predicates such
    as filesize tests, module expressions, entrypoint checks, or other UnknownNode
    content are represented as TRUE, except for the literal FALSE predicate.

    Treating an unsupported predicate as TRUE removes that predicate as a
    restriction.  Under AND this merely broadens the candidate set; under OR it can
    make the entire OR subtree TRUE, correctly signalling that no atom-only filter
    can safely represent that branch.

    The resulting expression is therefore an upper approximation of the searchable
    portion of the YARA condition: it may admit extra files, but it must not exclude
    a file solely because the broad planner cannot model part of the condition.
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
    """Return every physical stage key referenced anywhere in a Boolean expression.

    The function recursively walks AND, OR, and threshold children, collecting the
    keys from stage nodes into a set.  TRUE and FALSE nodes contribute no stages.
    Unknown planner operators raise immediately because silently ignoring a new
    operator could invalidate cost accounting or safety decisions.

    This helper is the common source of truth for stage-cost calculation, pruning,
    combined-stage selection, and cleanup of stages simplified out of a plan.
    """
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
    """Safely rewrite a Boolean expression to use only a selected set of stages.

    An unselected ordinary stage is replaced with TRUE, which removes that
    restriction and can only broaden an AND-based filter.  Composite expressions
    are recursively simplified with the normal Boolean constructors.

    Direct AND clauses containing only stage children are treated atomically after
    ``max_required_strings_per_and_search`` has chosen their allowed strings: if
    any member of that retained direct-AND clause is not selected, the entire
    clause becomes TRUE instead of silently shrinking to fewer mandatory strings.

    Threshold expressions are also atomic during budget pruning.  Either every
    stage required to represent the N-of expression is retained, preserving the
    original N exactly, or the whole threshold becomes TRUE.  This prevents budget
    selection from transforming, for example, 3-of-8 into a weaker 2-of-7 plan.

    The function is used only to create conservative broad-phase approximations;
    it never strengthens the original condition.
    """
    operator = expression[0]

    if operator == "stage":
        if expression[1] in selected_stage_keys:
            return expression
        return _BOOL_TRUE
    if operator in {"true", "false"}:
        return expression
    if operator == "and":
        children = expression[1]

        # A direct AND of string stages is an indivisible mandatory-string
        # clause for budget pruning. max_required_strings_per_and_search has
        # already decided how many strings may be retained in this clause.
        # Do not let max_required_string_searches_per_index silently remove
        # additional strings from it.
        #
        # If every selected string stage is available, preserve the complete
        # AND. Otherwise omit the whole clause by replacing it with TRUE.
        # This is conservative and cannot create a broad-phase false negative.
        if children and all(child[0] == "stage" for child in children):
            and_stage_keys = _expression_stage_keys(expression)
            if not and_stage_keys.issubset(selected_stage_keys):
                return _BOOL_TRUE
            return expression

        return _make_bool_and(_restrict_expression_to_stages(child, selected_stage_keys) for child in children)
    if operator == "or":
        return _make_bool_or(_restrict_expression_to_stages(child, selected_stage_keys) for child in expression[1])
    if operator == "threshold":
        # Keep N-of expressions atomic during budget pruning. Partially
        # selecting a threshold and replacing omitted children with TRUE would
        # lower the required count (for example, 3-of-8 could become 2-of-7).
        # That is a safe broad approximation, but it obscures the original
        # YARA semantics and weakens the filter. Either retain every searchable
        # stage referenced by this threshold, preserving the original N, or
        # replace the whole threshold with TRUE and let a sibling condition
        # provide the safe broad-phase restriction.
        threshold_stage_keys = _expression_stage_keys(expression)
        if not threshold_stage_keys.issubset(selected_stage_keys):
            return _BOOL_TRUE
        return expression

    raise ValueError(f"Unknown boolean broad-phase operator: {operator}")


def _stage_set_cost(stage_keys: set, stage_registry: dict) -> int:
    """Return the physical bgparse searches-per-index required by a set of stages.

    Each registered stage records its physical ``cost``: one for a normal
    single-search stage or combined AND batch, and more than one when a YARA string
    has alternative atom groups that must be searched separately and OR-unioned.
    The function sums those costs for the supplied stage keys.

    This value is used by preferred per-index budgeting and by the global hard task
    limit, so it measures physical searches rather than the number of logical YARA
    strings.
    """
    return sum(stage_registry[stage_key]["cost"] for stage_key in stage_keys)


def _minimum_restrictive_stage_set(expression, stage_registry: dict):
    """Find the lowest-cost stage set that keeps an expression meaningfully restrictive.

    This helper is used when the complete Boolean plan is more expensive than the
    configured preferred budget.  It asks what minimum collection of stages can be
    kept while replacing all omitted restrictions with TRUE without making the
    whole expression TRUE.

    For AND, one restrictive child can safely filter the original conjunction, so
    the cheapest safe child selection is chosen.  A direct string-only AND is an
    exception: after the configured AND-string limit has selected its members, the
    whole retained clause is treated atomically and all of its stages are required.
    For OR, every branch must remain restrictive, so the minimum selections for all
    branches are unioned.  Thresholds are likewise atomic and require every stage
    needed to preserve the original N-of semantics.

    The returned set is therefore the cheapest safe broad filter for that subtree,
    not an exact evaluation of the original YARA condition.
    """
    operator = expression[0]

    if operator == "true":
        return None
    if operator == "false":
        return set()
    if operator == "stage":
        return {expression[1]}

    if operator == "and":
        children = expression[1]

        # Direct string ANDs are kept intact after
        # max_required_strings_per_and_search has limited their size. This
        # keeps the configuration variable tied to the number of mandatory
        # strings in the AND clause instead of allowing the preferred
        # searches-per-index budget to prune more strings afterwards.
        if children and all(child[0] == "stage" for child in children):
            return _expression_stage_keys(expression)

        candidates = [_minimum_restrictive_stage_set(child, stage_registry) for child in children]
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
        # Thresholds are atomic for pruning. To preserve the original YARA
        # requirement exactly (for example 3 of 8 stays 3 of 8), every
        # searchable stage referenced by the threshold must be selected.
        #
        # If the complete threshold is too expensive, an enclosing AND may
        # safely choose another conjunct instead. An enclosing OR will require
        # this complete threshold because every OR branch must remain
        # restrictive to avoid false negatives.
        threshold_stage_keys = _expression_stage_keys(expression)
        if not threshold_stage_keys:
            return None
        return threshold_stage_keys

    raise ValueError(f"Unknown boolean broad-phase operator: {operator}")


def _collect_activation_bundles(expression, stage_registry: dict) -> list[set]:
    """Collect useful groups of stages that can progressively strengthen a pruned plan.

    The function recursively visits every Boolean subtree and asks
    ``_minimum_restrictive_stage_set`` for the minimum stage set that would make
    that subtree restrictive.  Each unique non-empty set is stored as an activation
    bundle.  The traversal then continues through AND, OR, and threshold children
    to discover smaller useful structures.

    ``_choose_boolean_stages`` uses these bundles when spare preferred-budget
    capacity exists.  Adding a complete bundle can restore meaningful Boolean
    structure, such as an OR branch or threshold, instead of spending budget on an
    individual stage that would simplify away and provide no additional filtering.
    """
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
    """Return a deterministic heuristic score for the expected usefulness of a stage.

    The score prefers stages with a longer extracted atom, then stages whose
    largest mandatory atom group contains more atoms, then lower physical search
    cost.  Sorted YARA labels provide a deterministic final tie-breaker.

    This is only a planning heuristic.  It does not affect correctness because
    stages omitted because of a preferred limit are replaced conservatively with
    TRUE.  The score exists to spend limited broad-phase work on searches that are
    more likely to reduce the narrow-phase candidate set.
    """
    return (
        stage["longest_atom"],
        stage["max_group_atom_count"],
        -stage["cost"],
        tuple(sorted(stage["labels"])),
    )


def _and_child_strength(expression, stage_registry: dict) -> tuple:
    """Estimate how valuable an AND operand is when only some conjuncts may be retained.

    The function recursively derives a deterministic strength tuple for a Boolean
    subexpression.  A stage uses its atom-length and atom-count hints directly.
    For OR, the weakest-looking alternative represents the branch because an OR is
    only as selective as its broadest alternative.  For an N-of threshold, the
    Nth-strongest child is used as a proxy for the selectivity of satisfying the
    threshold.  Nested ANDs use their strongest remaining child.

    Total physical cost, referenced stage count, and child count are included as
    tie-breakers so cheaper, simpler operands are preferred when selectivity looks
    similar.

    This score is used only when ``max_required_strings_per_and_search`` forces a
    choice between direct mandatory strings.  Omitted strings become TRUE, so the
    heuristic can change performance but not introduce a broad-phase false negative.
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
    """Apply the configured direct-string limit to every Boolean AND clause.

    The function recursively rewrites the Boolean expression.  OR and threshold
    subtrees are visited but do not consume the direct-string limit.  At an AND
    node, only immediate stage children count as direct mandatory strings.
    Complex operands such as ``A OR B`` or ``3 of (...)`` remain intact and are
    handled by their own Boolean semantics.

    If the number of direct string stages exceeds ``max_and_children``, those
    stages are ranked with ``_and_child_strength`` and only the strongest configured
    number are retained.  The omitted conjuncts are effectively replaced with TRUE
    by removing them from the AND, which creates a superset of the original matches
    and therefore remains safe for broad-phase filtering.

    The function also records structured limit events used by logging to explain
    exactly how many strings were present, which strings were kept, and which were
    omitted.  This setting controls logical direct-AND strings; it is separate from
    the physical searches-per-index budget.
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

        # This setting limits strings participating directly in an AND search,
        # not complex Boolean operands. Thresholds and OR clauses are evaluated
        # separately and must not consume this string count.
        direct_stage_children = [child for child in children if child[0] == "stage"]

        if len(direct_stage_children) <= max_and_children:
            return simplified

        ranked_stage_children = sorted(
            direct_stage_children,
            key=lambda child: (
                _and_child_strength(child, stage_registry),
                repr(child),
            ),
            reverse=True,
        )
        selected_stage_set = set(ranked_stage_children[:max_and_children])

        kept_children = [child for child in children if child[0] != "stage" or child in selected_stage_set]
        omitted_children = [child for child in direct_stage_children if child not in selected_stage_set]

        limit_events.append(
            {
                "original_count": len(direct_stage_children),
                "kept_count": len(selected_stage_set),
                "kept": tuple(child for child in children if child[0] == "stage" and child in selected_stage_set),
                "omitted": tuple(omitted_children),
            }
        )
        return _make_bool_and(kept_children)

    return visit(expression), limit_events


def _combine_single_search_and_stages(
    expression,
    stage_registry: dict,
):
    """Collapse compatible direct YARA-string ANDs into one native bgparse search.

    The function walks the Boolean expression recursively while preserving OR and
    threshold boundaries.  At each AND node it identifies immediate stage children
    whose physical cost is exactly one and whose stage contains exactly one bgparse
    search.  Two or more such stages can be represented exactly by concatenating
    all of their mandatory atoms into one command, because multiple bgparse ``-s``
    arguments have AND semantics.

    A canonical combined-stage key based on the constituent stage keys allows the
    same logical batch to be reused if it appears elsewhere in a different order.
    The combined stage carries the union of labels, group IDs, and atoms, has a
    physical cost of one, and replaces the individual batchable children in the
    Boolean tree.

    Stages with multiple alternatives, such as nocase expansions, are deliberately
    not combined.  Representing ``(A1 OR A2) AND (B1 OR B2)`` inside bgparse would
    require the Cartesian product of alternatives; naively placing every atom in
    one command would incorrectly require all alternatives and could cause false
    negatives.

    This optimisation reduces process count, temporary candidate sets, and
    Python-side intersections without changing the represented Boolean semantics.
    """
    operator = expression[0]

    if operator in {"true", "false", "stage"}:
        return expression

    if operator == "or":
        return _make_bool_or(_combine_single_search_and_stages(child, stage_registry) for child in expression[1])

    if operator == "threshold":
        return _make_bool_threshold(
            expression[1],
            [_combine_single_search_and_stages(child, stage_registry) for child in expression[2]],
        )

    if operator != "and":
        raise ValueError(f"Unknown boolean broad-phase operator: {operator}")

    simplified = _make_bool_and(_combine_single_search_and_stages(child, stage_registry) for child in expression[1])
    if simplified[0] != "and":
        return simplified

    children = list(simplified[1])
    batchable_children = [
        child
        for child in children
        if child[0] == "stage"
        and stage_registry[child[1]]["cost"] == 1
        and len(stage_registry[child[1]]["searches"]) == 1
    ]

    if len(batchable_children) < 2:
        return simplified

    # Canonicalise the constituent keys so the same logical AND batch can be
    # reused if it appears elsewhere in the expression in a different order.
    constituent_keys = tuple(
        sorted(
            (child[1] for child in batchable_children),
            key=repr,
        )
    )
    combined_stage_key = ("combined_and", constituent_keys)
    combined_stage = stage_registry.get(combined_stage_key)

    if combined_stage is None:
        constituent_stages = [stage_registry[stage_key] for stage_key in constituent_keys]

        combined_atoms = tuple(
            dict.fromkeys(atom for stage in constituent_stages for atom in stage["alternatives"][0])
        )
        if not combined_atoms:
            return simplified

        combined_group_ids = [group_id for stage in constituent_stages for group_id in stage["group_ids"]]
        combined_labels = set().union(*(stage["labels"] for stage in constituent_stages))
        label_groups = tuple(tuple(sorted(stage["labels"])) for stage in constituent_stages)

        combined_stage = {
            "key": combined_stage_key,
            "labels": combined_labels,
            "label_groups": label_groups,
            "combined_and": True,
            "group_ids": combined_group_ids,
            "alternatives": (combined_atoms,),
            "searches": [
                (
                    combined_group_ids[0],
                    _bgparse_search_string(list(combined_atoms)),
                )
            ],
            "cost": 1,
            "longest_atom": max(len(atom) for atom in combined_atoms),
            "max_group_atom_count": len(combined_atoms),
        }
        stage_registry[combined_stage_key] = combined_stage

    batchable_set = set(batchable_children)
    combined_child = ("stage", combined_stage_key)
    new_children = []
    combined_inserted = False

    for child in children:
        if child in batchable_set:
            if not combined_inserted:
                new_children.append(combined_child)
                combined_inserted = True
            continue

        new_children.append(child)

    return _make_bool_and(new_children)


def _choose_boolean_stages(
    expression,
    stage_registry: dict,
    preferred_searches_per_index: int,
    hard_searches_per_index: int,
):
    """Choose the strongest safe Boolean broad-phase plan allowed by search budgets.

    The function first calculates the physical cost of the complete expression.  If
    that cost fits both the preferred per-index budget and the hard per-index limit,
    the complete plan is returned unchanged.

    Otherwise it computes the minimum restrictive stage set required to keep the
    expression safely useful.  If even that minimum exceeds the hard limit, the
    hunt fails because executing an unsafe approximation is not permitted.  The
    preferred limit is softer: it may be exceeded when the minimum safe filter
    itself costs more, while the hard global-task-derived limit is never exceeded.

    Starting from the minimum safe selection, the function repeatedly considers
    activation bundles and individual stages that fit the remaining target budget.
    It scores additions by aggregate stage strength, useful stage count, added
    physical cost, and deterministic expression ordering.  After each addition the
    expression is re-restricted and any stages simplified out of the resulting
    Boolean tree are removed so their budget can be reused.

    The return value contains the selected expression, its referenced stage keys,
    its physical searches-per-index cost, and whether the complete plan was pruned.
    All pruning is performed through conservative TRUE replacement, so budgeting
    may increase narrow candidates but must not strengthen the YARA condition.
    """
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
    """Render a planned Boolean expression as readable YARA-oriented log text.

    TRUE and FALSE are rendered explicitly, stage nodes use their YARA labels,
    AND/OR nodes are recursively parenthesised, and threshold nodes are shown as
    ``AT_LEAST_N(...)``.  Combined native bgparse AND stages are described through
    ``_stage_label_text`` so logs show the logical mandatory strings rather than an
    opaque internal stage key.

    The formatter is diagnostic only.  Its purpose is to make the planner's exact
    broad-phase interpretation auditable against the original YARA condition.
    """
    operator = expression[0]
    if operator == "true":
        return "TRUE (no safe atom restriction)"
    if operator == "false":
        return "FALSE"
    if operator == "stage":
        return _stage_label_text(stage_registry[expression[1]])
    if operator == "and":
        return "(" + " AND ".join(_format_boolean_expression(child, stage_registry) for child in expression[1]) + ")"
    if operator == "or":
        return "(" + " OR ".join(_format_boolean_expression(child, stage_registry) for child in expression[1]) + ")"
    if operator == "threshold":
        children = ", ".join(_format_boolean_expression(child, stage_registry) for child in expression[2])
        return f"AT_LEAST_{expression[1]}({children})"

    raise ValueError(f"Unknown boolean broad-phase operator: {operator}")


def _evaluate_boolean_expression(expression, stage_matches: dict) -> set[str]:
    """Evaluate the final Boolean plan over the candidate sets returned by bgparse.

    A stage node resolves to the set of indexed paths found for that stage.  AND
    recursively evaluates its children, sorts their result sets from smallest to
    largest, and intersects them in place so rejection happens early and temporary
    set work is minimised.  OR unions all child candidate sets.  A threshold counts
    how many child result sets contain each path and returns paths whose count meets
    or exceeds the required N.

    FALSE evaluates to an empty set.  TRUE is intentionally rejected because a
    nonrestrictive plan should have been handled earlier by fallback planning rather
    than accidentally sending an undefined universe of files to narrow phase.

    This is the point where logical YARA-level relationships between independently
    executed broad stages are enforced before candidates are handed to exact
    narrow-phase YARA.
    """
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
        return result

    if operator == "threshold":
        required = expression[1]
        counts: dict[str, int] = {}

        for child in expression[2]:
            for path in _evaluate_boolean_expression(child, stage_matches):
                counts[path] = counts.get(path, 0) + 1
        return {path for path, count in counts.items() if count >= required}

    raise ValueError(f"Unknown boolean broad-phase operator: {operator}")


def _build_rule_boolean_plan(
    rule_name: str,
    plan,
    max_required_strings: int,
    preferred_searches_per_index: int,
    hard_searches_per_index: int,
):
    """Build one rule's executable, resource-bounded broad-phase Boolean plan.

    The function converts the parsed condition AST into a safe searchable
    expression and a registry of physical string stages.  If no restrictive
    expression can be represented but usable atoms exist, it falls back to the
    OR-all-atoms compatibility plan.

    For a representable expression it first applies
    ``max_required_strings_per_and_search`` to direct string-only AND clauses.  It
    then batches compatible single-search direct AND strings into one native
    bgparse command.  After batching, ``_choose_boolean_stages`` applies the
    preferred searches-per-index budget and the hard global-task-derived limit.
    This order is deliberate: the logical direct-string limit is decided before
    physical batching, and the budget sees the true physical cost after batching.

    FALSE conditions return an empty executable plan.  A selected TRUE expression
    falls back to OR-all-atoms rather than pretending to be restrictive.  Selected
    stages are finally sorted deterministically using selectivity and cost hints for
    predictable execution and logging.

    The returned dictionary contains the execution mode, selected Boolean
    expression, ordered stages, full stage registry, physical searches per index,
    whether budget pruning occurred, and any direct-AND limit events.
    """
    stage_registry = {}
    condition_ast = getattr(plan, "condition_ast", None)
    expression = _build_searchable_boolean_expression(
        condition_ast,
        plan,
        stage_registry,
    )
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

    # Direct mandatory strings with one physical atom-group search each can be
    # executed as one bgparse command containing multiple -s arguments. This
    # preserves exact AND semantics while avoiding separate broad result sets
    # and a later Python-side intersection.
    expression = _combine_single_search_and_stages(
        expression,
        stage_registry,
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
    """Execute one physical bgparse task against one index and stream its results.

    A shell command is built from the bgparse executable, the already-generated
    search arguments, and the target index.  stdout is kept as a pipe and parsed
    incrementally by ``_process_bgparse_lines`` so a large result set is not first
    materialised as one giant bytes object.  stderr is redirected to a temporary
    file, preventing either subprocess pipe from filling and blocking the child.

    The parsed match paths and optional file metadata are returned together with
    the process return code, stderr contents, and identifying task information.
    The caller performs the central error handling so all executor tasks follow the
    same path.

    Cancellation is checked after the subprocess has exited.  This helper is kept
    small and side-effect-limited so it can be submitted safely to the bounded
    broad-phase ThreadPoolExecutor.
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
    """Adapter that executes a pre-built broad-phase task tuple.

    Broad-phase task generation stores every argument needed by
    ``_run_bgparse_task`` in a tuple.  ThreadPoolExecutor submission is simpler and
    less error-prone when all tasks have the same one-argument callable, so this
    helper only unpacks the tuple and forwards it unchanged.

    It intentionally contains no search logic of its own.
    """
    return _run_bgparse_task(*task)


def _broad_phase_search(
    query_type: int,
    indices: list[str],
    rule_search_plans: RuleSearchPlans,
    progress_callback: ProgressCallback,
    query_hash: str,
) -> tuple[RuleFileMatches, FileConfig]:
    """Plan and execute the atom-index broad phase for all rules in a hunt.

    For YARA rules, the function builds a safe Boolean broad plan from each parsed
    condition.  YARA strings are represented as ORs of their alternative atom
    groups, direct mandatory single-search strings may be batched into native
    multi-``-s`` bgparse commands, and AND, OR, and N-of relationships are later
    evaluated over the resulting candidate sets.  Unsupported predicates are
    handled conservatively by the planner so broad phase can admit extra files but
    does not intentionally strengthen the original condition.

    Configuration controls three separate resource concerns: the maximum number of
    direct strings retained in an AND clause, the preferred number of physical
    searches per index, and the hard total broad-task limit.  A hard per-index limit
    is derived from the total task cap and current number of indexes.  The complete
    multi-rule task count is checked again before any subprocess work starts.

    Execution is stage-oriented.  Each physical stage is searched across every
    index with a bounded ThreadPoolExecutor that keeps at most the configured number
    of bgparse processes in flight.  stdout is parsed incrementally, candidate paths
    are unioned across indexes and across alternative searches belonging to the
    same stage, and file metadata is retained only as needed for later narrow
    fetches.  Progress, cancellation, process failures, bgparse error markers, and
    expected task counts are checked throughout.

    After all stages for a rule finish, ``_evaluate_boolean_expression`` applies
    the planned AND/OR/threshold set logic and produces the exact broad candidate
    superset sent to narrow phase.  Per-stage temporary structures are then cleared
    and memory trimming is requested before moving to the next rule.

    The broad phase never performs final YARA matching; its purpose is to use the
    indexes to reduce the amount of original file data that narrow phase must fetch
    while preserving the planner's conservative no-false-negative design.
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
            if stage.get("combined_and"):
                logger.info(
                    'Rule "%s": boolean stage %d/%d batches mandatory AND strings %s into one bgparse search: %s',
                    rule_name,
                    stage_number,
                    len(rule_plan["stages"]),
                    _stage_label_text(stage),
                    stage["searches"][0][1].strip(),
                )
            else:
                logger.info(
                    'Rule "%s": boolean stage %d/%d represents %s with %d alternative atom-group searches: %s',
                    rule_name,
                    stage_number,
                    len(rule_plan["stages"]),
                    _stage_label_text(stage),
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
                _stage_label_text(stage),
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
    """Parse bgparse stdout incrementally into match paths and optional file metadata.

    Each non-empty output line is split on commas.  The first field is decoded as
    the indexed file path; remaining key=value fields, excluding bgparse's final
    trailing field, are decoded into the per-file configuration mapping when
    ``store_config`` is enabled.  Existing config entries are left intact so the
    first usable metadata record for a path is retained.

    ``allowed_paths`` can further restrict accepted results when a caller needs to
    filter a streamed search.  Malformed config fields increment the bgparse error
    metric and raise ``FileConfigReadException`` rather than silently storing
    corrupt metadata.

    The function checks the shared cancellation event while consuming lines and
    returns the paths parsed from this stream plus the updated config mapping.
    Streaming is used to avoid holding complete potentially-large bgparse stdout in
    memory.
    """
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
    """Compatibility wrapper for callers that already hold complete bgparse output bytes.

    The byte buffer is split into lines and delegated to
    ``_process_bgparse_lines`` so tests and legacy callers use exactly the same
    parsing, validation, metric, and metadata behaviour as the streaming
    broad-phase subprocess path.

    New broad-phase execution uses the line-oriented parser directly to avoid
    materialising large stdout buffers.
    """
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
    """Run exact per-file matching on the candidate superset produced by broad phase.

    STRING searches require no file bodies and return the broad matches directly.
    For YARA and Suricata candidates, the function converts rule-path lists to sets,
    builds an inverted file-to-rules mapping so each candidate file is fetched only
    once, and precompiles each YARA rule once for the hunt.  YARA source is given a
    PE import when required by the surrounding Retrohunt behaviour.

    A bounded ThreadPoolExecutor processes files end-to-end: one worker owns one
    file fetch and then evaluates every candidate rule associated with that file.
    This intentionally overlaps blocking dispatcher I/O with YARA CPU work while
    limiting the number of complete file bodies simultaneously resident in memory.
    The broad-phase file metadata entry is popped as soon as its file is fetched,
    and worker-local data references are cleared in ``finally`` so errors or
    timeouts do not pin large buffers.

    Candidates are processed in cleanup batches sized from the active worker count
    and the configured cleanup multiplier.  Each completed file immediately updates
    rule match sets, progress, I/O and CPU metrics, missing-file accounting, and the
    data-release callback.  After a bounded batch drains, temporary containers are
    cleared and explicit garbage collection/native heap trimming is requested.

    At the end, only paths that passed exact narrow matching remain.  Native YARA
    objects, candidate maps, metrics caches, and file metadata are cleared before a
    final memory trim.  This phase is the correctness authority: broad phase only
    reduces candidates, while narrow phase evaluates the original rule semantics.
    """
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

    configured_threads = settings.max_thread_count
    active_workers = min(configured_threads, total_files)
    cleanup_batch_size = active_workers * settings.default_narrow_phase_cleanup_multiplier

    # Worker function. A worker holds at most one complete file body. data is
    # deleted in finally so YARA timeouts/errors cannot pin a large bytes object
    # inside a traceback retained by a Future.
    def worker(file_path: str, rules_for_file: set[str]):
        """Fetch and exactly evaluate one candidate file against all rules assigned to it.

        The worker first removes the file's broad-phase metadata from ``file_config`` so
        that table shrinks continuously during the hunt.  It then performs the blocking
        data callback, records I/O duration and byte count, and treats an empty result
        as a missing file.

        For each rule associated with the file, YARA matching is timed and configured
        to abort its callback path on the first confirmed match.  Cancellation is
        checked before the fetch, after the blocking fetch returns, and between rule
        evaluations.  Suricata follows the same per-file dispatch structure when that
        implementation is available.

        The complete file body is intentionally scoped to this worker invocation and
        set to None in ``finally``.  This prevents large bytes objects from being held
        by worker frames or Future tracebacks after success, timeout, cancellation, or
        an exception.
        """
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
        """Unpack one ``(file_path, rules_for_file)`` item and execute the narrow worker.

        The narrow batch submits dictionary items directly to ThreadPoolExecutor.  This
        adapter keeps submission uniform while leaving all fetch, match, cancellation,
        and cleanup behaviour inside ``worker``.
        """
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
        """Execute one bounded narrow-phase batch and consume every Future immediately.

        All files in the supplied batch are submitted to the shared executor.  Futures
        are then processed with ``as_completed`` so completed files release metadata and
        update result sets without waiting for slower files in the same batch.

        For each completed worker result the function records I/O metrics, advances
        file and rule/job progress, removes missing or non-matching paths from the rule
        candidate sets, and invokes the data-release callback after progress consumers
        have had a chance to use matched-file metadata.  Worker exceptions also trigger
        the release callback before being re-raised.

        The local Future mapping is destructively drained and cleared in ``finally``.
        Combined with outer batch clearing and ``release_unused_memory``, this bounded
        lifetime prevents completed Future objects, worker results, and per-file
        metadata from accumulating across very large hunts.
        """
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
    """Yield bounded dictionaries while destructively draining the source mapping.

    Up to ``chunk_size`` entries are removed from the input dictionary with
    ``popitem`` and returned as a new batch.  The process repeats until the source
    is empty.  A non-positive chunk size is rejected because it could otherwise
    create a non-progressing loop.

    Narrow phase uses destructive chunking so files already assigned to a completed
    cleanup batch are no longer referenced by the large file-to-rules mapping.
    This is a memory-lifetime optimisation, not merely a batching convenience.
    """
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
