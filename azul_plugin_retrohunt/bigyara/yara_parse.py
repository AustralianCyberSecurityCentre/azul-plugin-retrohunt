"""Parsing of yara rules to extract string atoms for search."""

# type hint for AtomTreeNode.children
from __future__ import annotations

import ast
import binascii
import logging
import os
import re
import subprocess  # noqa: S404  # nosec: B404
import tempfile
from dataclasses import dataclass, field
from itertools import product

from azul_plugin_retrohunt.bigyara.env import executables

from . import SEARCH_ATOM_SIZE_MIN, ProgressCallback, SearchPhaseEnum

logger = logging.getLogger("bigyara.yara_atom_parser")


class YaraStringNoAtomException(Exception):
    """No valid atoms were found in the yara string."""

    pass


# FUTURE: check if there are more of these now that need to be supported.
class YaraStringFlagEnum:
    """Enum of the codes used by yara internally for string modifiers."""

    HEXADECIMAL = 0x02
    NO_CASE = 0x04
    ASCII = 0x08
    WIDE = 0x10
    REGEXP = 0x20
    FULL_WORD = 0x80
    ANONYMOUS = 0x100
    XOR = 0x80000
    LAST_FLAG = XOR


class YaraString:
    """Representation of a yara string."""

    name: str
    atoms: list[bytes]
    modifiers: list[str]
    re: bytes


class YaraRule:
    """Representation of a yara rule."""

    name: str
    strings: list[YaraString]
    content: bytes


@dataclass
class ConditionNode:
    """Condition node."""

    pass


@dataclass
class UnknownNode(ConditionNode):
    """Condition fragment that is not understood by the broad-phase parser."""

    raw_text: str = ""


@dataclass
class StringNode(ConditionNode):
    """String node."""

    string_name: str


@dataclass
class AndNode(ConditionNode):
    """And node."""

    children: list[ConditionNode]


@dataclass
class OrNode(ConditionNode):
    """Or node."""

    children: list[ConditionNode]


@dataclass
class NOfNode(ConditionNode):
    """None of node."""

    required: int
    children: list[ConditionNode]


@dataclass
class RuleSearchPlan:
    """Search plan object."""

    condition_ast: ConditionNode | None = None

    string_groups: dict[str, list[int]] = field(default_factory=dict)

    atoms: list[bytes] = field(default_factory=list)

    # OR of groups
    groups: list[set[bytes]] = field(default_factory=list)

    # condition metadata
    condition_type: str = "unknown"

    # n of them
    required_count: int | None = None

    # total strings available
    string_count: int | None = None

    # $a and $b and <complex_expression>
    required_strings: set[str] = field(default_factory=set)

    required_groups: list[set[bytes]] = field(default_factory=list)

    optional_strings: set[str] = field(default_factory=set)

    raw_condition: str = ""


# these are redefined aliases from the search module to avoid circular dependency
RuleFileMatches = dict[str, list[str]]
RuleAtoms = dict[str, list[bytes]]
RuleContent = dict[str, bytes]
RuleSearchPlans = dict[str, RuleSearchPlan]


def _parse_condition_metadata(
    condition_text: str,
    string_count: int,
) -> tuple[str, int | None]:
    """Extract simple condition metadata from a YARA condition."""
    if re.search(r"\bany\s+of\s+them\b", condition_text, re.IGNORECASE):
        return ("any", 1)

    if re.search(r"\ball\s+of\s+them\b", condition_text, re.IGNORECASE):
        return ("all", string_count)

    match = re.search(
        r"\b(\d+)\s+of\s+them\b",
        condition_text,
        re.IGNORECASE,
    )
    if match:
        return ("n_of", int(match.group(1)))

    return ("unknown", None)


def _convert_condition_ast(node) -> ConditionNode:
    """Convert Python AST into broad-phase AST."""
    #
    # N(2, ...)
    #
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "N":
        required = node.args[0].value

        children = []

        for arg in node.args[1:]:
            children.append(_convert_condition_ast(arg))

        return NOfNode(
            required=required,
            children=children,
        )

    #
    # S("$a")
    #
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "S":
        return StringNode(
            string_name=node.args[0].value,
        )

    #
    # a & b
    #
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitAnd):
        left = _convert_condition_ast(node.left)
        right = _convert_condition_ast(node.right)

        children = []

        if isinstance(left, AndNode):
            children.extend(left.children)
        else:
            children.append(left)

        if isinstance(right, AndNode):
            children.extend(right.children)
        else:
            children.append(right)

        return AndNode(children)

    #
    # a | b
    #
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _convert_condition_ast(node.left)
        right = _convert_condition_ast(node.right)

        children = []

        if isinstance(left, OrNode):
            children.extend(left.children)
        else:
            children.append(left)

        if isinstance(right, OrNode):
            children.extend(right.children)
        else:
            children.append(right)

        return OrNode(children)

    raise ValueError(f"Unsupported AST node: {ast.dump(node)}")


def _expand_string_specifiers(
    specifiers: list[str],
    string_names: set[str],
) -> list:
    """Expand explicit string names and wildcard patterns."""
    expanded: list[str] = []

    for specifier in specifiers:
        specifier = specifier.strip()

        if specifier.endswith("*"):
            prefix = specifier[:-1]

            expanded.extend(sorted(name for name in string_names if name.startswith(prefix)))
        elif specifier in string_names:
            expanded.append(specifier)

    return expanded


def _rewrite_special_conditions(
    condition_text: str,
    string_names: set[str],
) -> str:
    """Rewrite YARA any/all/n-of expressions into boolean form."""

    def repl(match):
        quantity = match.group(1).lower()
        target = match.group(2)

        if target.lower() == "them":
            strings = sorted(string_names)
        else:
            specifiers = [item.strip() for item in target[1:-1].split(",")]

            strings = _expand_string_specifiers(
                specifiers,
                string_names,
            )

        if not strings:
            return "False"

        #
        # any of (...)
        #
        if quantity == "any":
            return "(" + " or ".join(strings) + ")"

        #
        # all of (...)
        #
        if quantity == "all":
            return "(" + " and ".join(strings) + ")"

        required = int(quantity)

        return "N(" + str(required) + "," + ",".join(strings) + ")"

    return re.sub(
        r"\b(any|all|\d+)\s+of\s*(them|\(.*?\))",
        repl,
        condition_text,
        flags=re.IGNORECASE,
    )


def _previous_significant_word(text: str, index: int) -> str:
    """Return the word immediately before index, ignoring whitespace."""
    index -= 1

    while index >= 0 and text[index].isspace():
        index -= 1

    end = index + 1

    while index >= 0 and (text[index].isalnum() or text[index] == "_"):
        index -= 1

    return text[index + 1 : end].lower()


def _mask_non_code_regions(expr: str) -> str:
    """Mask strings, regex literals, and comments while preserving positions.

    Every masked character is replaced with a space, except newlines, which are
    retained. Keeping the same string length allows the boolean splitters to use
    indexes from the masked text against the original expression.

    Supported protected regions:
        "quoted strings"
        /regular expressions/
        // line comments
        /* block comments */

    A slash begins a regex literal only when it follows the YARA `matches`
    keyword. Other slashes are left untouched so arithmetic division is not
    mistaken for a regex.
    """
    masked = list(expr)
    index = 0
    length = len(expr)

    def mask_range(start: int, stop: int) -> None:
        for position in range(start, stop):
            if expr[position] not in "\r\n":
                masked[position] = " "

    while index < length:
        char = expr[index]

        # Line comment.
        if char == "/" and index + 1 < length and expr[index + 1] == "/":
            start = index
            index += 2

            while index < length and expr[index] not in "\r\n":
                index += 1

            mask_range(start, index)
            continue

        # Block comment.
        if char == "/" and index + 1 < length and expr[index + 1] == "*":
            start = index
            index += 2

            while index + 1 < length and not (expr[index] == "*" and expr[index + 1] == "/"):
                index += 1

            if index + 1 < length:
                index += 2
            else:
                index = length

            mask_range(start, index)
            continue

        # Double-quoted string literal.
        if char == '"':
            start = index
            index += 1
            escaped = False

            while index < length:
                current = expr[index]

                if escaped:
                    escaped = False
                    index += 1
                    continue

                if current == "\\":
                    escaped = True
                    index += 1
                    continue

                if current == '"':
                    index += 1
                    break

                index += 1

            mask_range(start, index)
            continue

        # YARA regex literal used with the `matches` operator.
        if char == "/" and _previous_significant_word(expr, index) == "matches":
            start = index
            index += 1
            escaped = False
            in_character_class = False

            while index < length:
                current = expr[index]

                if escaped:
                    escaped = False
                    index += 1
                    continue

                if current == "\\":
                    escaped = True
                    index += 1
                    continue

                if current == "[":
                    in_character_class = True
                    index += 1
                    continue

                if current == "]" and in_character_class:
                    in_character_class = False
                    index += 1
                    continue

                if current == "/" and not in_character_class:
                    index += 1

                    # Consume optional regex modifiers.
                    while index < length and expr[index].isalpha():
                        index += 1

                    break

                index += 1

            mask_range(start, index)
            continue

        index += 1

    return "".join(masked)


def _strip_outer_parentheses(expr: str) -> str:
    """Strip balanced parentheses that wrap the complete expression.

    Parentheses inside strings, regex literals, and comments are ignored.
    """
    expr = expr.strip()

    while expr.startswith("(") and expr.endswith(")"):
        masked = _mask_non_code_regions(expr)
        depth = 0
        wraps_entire_expression = True

        for index, char in enumerate(masked):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1

                if depth == 0 and index != len(masked) - 1:
                    wraps_entire_expression = False
                    break

            if depth < 0:
                wraps_entire_expression = False
                break

        if not wraps_entire_expression or depth != 0:
            break

        expr = expr[1:-1].strip()

    return expr


def _split_top_level_boolean(expr: str, operator: str) -> list[str]:
    """Split on a top-level boolean keyword outside protected regions."""
    parts: list[str] = []
    depth = 0
    start = 0
    index = 0
    operator_lower = operator.lower()
    masked = _mask_non_code_regions(expr)
    masked_lower = masked.lower()

    while index < len(masked):
        char = masked[index]

        if char == "(":
            depth += 1
            index += 1
            continue

        if char == ")":
            depth = max(0, depth - 1)
            index += 1
            continue

        if depth == 0 and masked_lower.startswith(operator_lower, index):
            before = masked[index - 1] if index > 0 else " "
            after_index = index + len(operator)
            after = masked[after_index] if after_index < len(masked) else " "

            if not (before.isalnum() or before == "_") and not (after.isalnum() or after == "_"):
                parts.append(expr[start:index].strip())
                start = after_index
                index = after_index
                continue

        index += 1

    if parts:
        parts.append(expr[start:].strip())
        return parts

    return [expr.strip()]


def _split_top_level_commas(expr: str) -> list[str]:
    """Split top-level commas outside strings, regexes, and comments."""
    parts: list[str] = []
    depth = 0
    start = 0
    masked = _mask_non_code_regions(expr)

    for index, char in enumerate(masked):
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            parts.append(expr[start:index].strip())
            start = index + 1

    parts.append(expr[start:].strip())
    return parts


def _parse_partial_condition(expr: str) -> ConditionNode:
    """Parse the boolean/string portions of a YARA condition conservatively.

    Unsupported predicates become UnknownNode instances. This allows a condition
    such as:

        filesize > 2MB and ($a or $b)

    to retain the searchable ($a or $b) subtree without pretending that the
    unsupported filesize predicate was evaluated.
    """
    expr = _strip_outer_parentheses(expr)

    if not expr:
        return UnknownNode(raw_text=expr)

    # OR has lower precedence than AND, so split OR first.
    or_parts = _split_top_level_boolean(expr, "or")
    if len(or_parts) > 1:
        return OrNode(children=[_parse_partial_condition(part) for part in or_parts])

    and_parts = _split_top_level_boolean(expr, "and")
    if len(and_parts) > 1:
        return AndNode(children=[_parse_partial_condition(part) for part in and_parts])

    n_of_match = re.fullmatch(
        r"N\s*\(\s*(\d+)\s*,(.*)\)",
        expr,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if n_of_match:
        required = int(n_of_match.group(1))
        child_text = n_of_match.group(2)
        children = [_parse_partial_condition(part) for part in _split_top_level_commas(child_text) if part.strip()]
        return NOfNode(required=required, children=children)

    if re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", expr):
        return StringNode(string_name=expr)

    return UnknownNode(raw_text=expr)


def _build_condition_ast(
    condition_text: str,
    string_names: set[str],
) -> ConditionNode | None:
    """Build a conservative partial AST from a YARA condition.

    Boolean string expressions are retained. Unsupported YARA predicates are
    represented as UnknownNode objects instead of causing the complete parse
    to fail.
    """
    expr = _rewrite_special_conditions(
        condition_text,
        string_names,
    )

    logger.info(
        "Rewritten condition expression: %s",
        expr,
    )

    try:
        condition_ast = _parse_partial_condition(expr)

        logger.info(
            "Partial condition AST: %s",
            condition_ast,
        )

        return condition_ast
    except Exception as exc:
        logger.debug(
            "Failed to parse partial condition AST: %s",
            exc,
        )
        return None


def _evaluate_condition_ast(
    node: ConditionNode | None,
    string_matches: dict[str, set[str]],
) -> set:
    """Evaluate broad-phase condition tree."""
    if node is None:
        return set()

    if isinstance(node, UnknownNode):
        return set()

    if isinstance(node, StringNode):
        return string_matches.get(
            node.string_name,
            set(),
        )

    if isinstance(node, OrNode):
        results = [
            _evaluate_condition_ast(
                child,
                string_matches,
            )
            for child in node.children
        ]

        if not results:
            return set()

        return set.union(*results)

    if isinstance(node, AndNode):
        results = [
            _evaluate_condition_ast(
                child,
                string_matches,
            )
            for child in node.children
        ]

        if not results:
            return set()

        return set.intersection(*results)

    if isinstance(node, NOfNode):
        counts: dict[str, int] = {}

        for child in node.children:
            matches = _evaluate_condition_ast(
                child,
                string_matches,
            )

            for path in matches:
                counts[path] = counts.get(path, 0) + 1

        return {path for path, count in counts.items() if count >= node.required}

    raise ValueError(f"Unsupported condition node: {type(node)}")


def _extract_required_groups(
    node: ConditionNode | None,
    string_groups: dict[str, list[int]],
    groups: list[set[bytes]],
) -> list[set[bytes]]:
    """Return searchable groups from required top-level OR branches.

    For a condition such as:

        filesize > 2MB and ($a or $b)

    the unsupported filesize predicate is ignored for broad-phase planning and
    the individual atom groups belonging to $a and $b are returned. The search
    layer then runs each group independently and ORs their candidate results.

    Only OR expressions that are direct children of a top-level AND are used.
    This is conservative: an OR at the root is not guaranteed to be required.
    """
    if not isinstance(node, AndNode):
        return []

    required_groups: list[set[bytes]] = []
    seen_group_ids: set[int] = set()

    for child in node.children:
        if not isinstance(child, OrNode):
            continue

        for sub in child.children:
            if not isinstance(sub, StringNode):
                continue

            for group_idx in string_groups.get(sub.string_name, []):
                if group_idx in seen_group_ids:
                    continue

                if 0 <= group_idx < len(groups):
                    required_groups.append(groups[group_idx])
                    seen_group_ids.add(group_idx)

    return required_groups


def _required_strings_from_ast(node: ConditionNode | None) -> set[str]:
    """Return strings that are guaranteed to be present for the condition to be true."""
    if node is None:
        return set()

    if isinstance(node, UnknownNode):
        return set()

    if isinstance(node, StringNode):
        return {node.string_name}

    if isinstance(node, AndNode):
        # All children must match → union of required
        required = set()
        for child in node.children:
            required |= _required_strings_from_ast(child)
        return required

    if isinstance(node, OrNode):
        # Any child can match → intersection of required
        child_required = [_required_strings_from_ast(child) for child in node.children]

        if not child_required:
            return set()

        result = child_required[0].copy()
        for s in child_required[1:]:
            result &= s
        return result

    if isinstance(node, NOfNode):
        # Only safe if ALL are required (i.e. N == len(children))
        if node.required == len(node.children):
            required = set()
            for child in node.children:
                required |= _required_strings_from_ast(child)
            return required

        return set()

    return set()


def _extract_required_strings(
    condition_text: str,
) -> set:
    """Extract string identifiers that are definitely required.

    Examples:
    $a and $b -> {"$a", "$b"}

    $a and $b and some_complex_expression -> {"$a", "$b"}

    $a or $b -> set()

    $cfg_blob and
    $sleep_mask and
    for any i in (1..#s1): ( @s1[i] < @s2[1] ) -> {"$cfg_blob", "$sleep_mask"}
    """
    required: set[str] = set()

    parts = re.split(
        r"\band\b",
        condition_text,
        flags=re.IGNORECASE,
    )

    for part in parts:
        part = part.strip()

        if re.fullmatch(
            r"\$[A-Za-z_][A-Za-z0-9_]*",
            part,
        ):
            required.add(part)

    return required


def parse_yara_rules(
    rule_text: str, progress_callback: ProgressCallback
) -> tuple[RuleAtoms, RuleContent, RuleSearchPlans]:
    """Compile the yara rule, parsing out search atoms.

    Will parse the yara rule with small atoms first to determine
    whether there are any nocase strings. If there are, we'll have to stick
    with small atoms, otherwise we can use the large atom version
    """
    yara_rules: list[YaraRule]
    rule_atoms: RuleAtoms = {}
    rule_search_plans: RuleSearchPlans = {}

    # write the yara rules to a file
    tmp_path: str
    with tempfile.NamedTemporaryFile(suffix=".yar", mode="w", delete=False) as yara_file:
        yara_file.write(rule_text)
        tmp_path = yara_file.name

    # FUTURE: This section of code needs to be re-thought.
    #         It seems silly to do an entire run-through of yara just to detect nocase strings.
    #         I see no reason why we can't just detect nocase with regex or something,
    #         then warn that it will be time consuming.
    #         Alternately, could just blanket-ban nocase and say that bigyara is not compatible with it.
    yara_rules = _parse_yara_with_exe(executables["yarac-small"], tmp_path)
    nocase: bool = False
    for yara_rule in yara_rules:
        for string in yara_rule.strings:
            if "nocase" in string.modifiers:
                logger.warning(
                    f"String {string.name} in rule {yara_rule.name} has the 'nocase' modifier - "
                    "this may severely degrade performance"
                )
                nocase = True
                break
        if nocase:
            break
    if not nocase:
        yara_rules = _parse_yara_with_exe(executables["yarac-large"], tmp_path)

    # delete the yara rule file
    os.remove(tmp_path)

    progress_callback(SearchPhaseEnum.ATOM_PARSE, 0, len(yara_rules), None)

    for rule_index in range(len(yara_rules)):
        new_atoms: list[bytes] = []
        search_group_count = 0
        largest_group = 0
        # accumulate all regex groups across the entire rule.

        groups: list[set[bytes]] = []
        group_sizes: list[int] = []
        string_groups: dict[str, list[int]] = {}

        for string_idx, yara_string in enumerate(yara_rules[rule_index].strings):
            string_name = yara_string.name

            # Anonymous YARA strings ($ = ...)
            # must be treated as distinct strings.
            if string_name == "$":
                string_name = f"$anon_{string_idx}"

            string_groups[string_name] = []
            if "nocase" not in yara_string.modifiers and len(yara_string.re) > 0:
                # If it is nocase or a normal string, the searches are the atoms
                # if it is a regular expression, pull the searches from the RE tree
                # FUTURE: this function does a heap of unnecessary work and needs to be refactored.

                # inspect regex structure before flattening atoms.
                try:
                    re_tree_root: AtomTreeNode = _parse_re_tree(yara_string.re)

                    regex_searches: list[set] = _searches_from_node(re_tree_root)
                    regex_searches = _remove_bad_atoms(regex_searches)
                    regex_searches = _get_minimal_atoms(regex_searches)

                    # keep all groups for logging later.
                    for search in regex_searches:
                        groups.append(set(search))

                        string_groups[string_name].append(len(groups) - 1)

                    group_sizes.extend(len(g) for g in regex_searches)

                    search_group_count += len(regex_searches)

                    if regex_searches:
                        largest_group = max(
                            largest_group,
                            max(len(x) for x in regex_searches),
                        )

                except Exception as e:
                    logger.debug(
                        "Failed to inspect regex structure for string %s in rule %s: %s",
                        yara_string.name,
                        yara_rules[rule_index].name,
                        e,
                    )

                yara_string.atoms = _get_atoms_from_regex(
                    yara_string.re,
                    yara_string.modifiers,
                )

            if len(yara_string.atoms) == 0:
                logger.error(
                    "No atoms found: rule=%s string=%s modifiers=%s regex=%r",
                    yara_rules[rule_index].name,
                    yara_string.name,
                    yara_string.modifiers,
                    yara_string.re,
                )

                raise YaraStringNoAtomException(
                    f"Failed to find any valid atoms for string {yara_string.name} in {yara_rules[rule_index].name}"
                )

            for yara_atom in yara_string.atoms:
                if yara_atom not in new_atoms:
                    new_atoms.append(yara_atom)

            # non-regex strings become singleton groups
            if len(yara_string.re) == 0 or "nocase" in yara_string.modifiers:
                for yara_atom in yara_string.atoms:
                    groups.append({yara_atom})

                    string_groups[string_name].append(len(groups) - 1)

        progress_callback(
            SearchPhaseEnum.ATOM_PARSE,
            rule_index + 1,
            len(yara_rules),
            (yara_rules[rule_index].name, new_atoms),
        )

        rule_name = yara_rules[rule_index].name

        rule_atoms[rule_name] = new_atoms

        rule_search_plans[rule_name] = RuleSearchPlan(
            string_groups=string_groups,
            atoms=new_atoms.copy(),
            groups=groups,
            string_count=len(yara_rules[rule_index].strings),
        )

        logger.info(f'Found {len(rule_atoms[rule_name])} atoms for "{rule_name}"')

    rule_content: RuleContent = {}

    condition_re = re.compile(
        r"rule (.+?)(?:\:.+?)?{.+?condition:(.+?)}",
        re.DOTALL,
    )

    for match in re.finditer(condition_re, rule_text):
        re_rule_name = match.group(1).strip()
        condition_text = match.group(2).strip()

        for match_rule_name in rule_atoms:
            if match_rule_name != re_rule_name:
                continue

            rule_content[match_rule_name] = match.group(0)

            if match_rule_name in rule_search_plans:
                plan = rule_search_plans[match_rule_name]

                plan.raw_condition = condition_text

                try:
                    plan.condition_ast = _build_condition_ast(
                        condition_text,
                        set(plan.string_groups.keys()),
                    )

                    logger.debug(
                        'Rule "%s" condition AST: %s',
                        match_rule_name,
                        plan.condition_ast,
                    )
                except Exception as exc:
                    logger.debug(
                        'Rule "%s" failed AST parse: %s',
                        match_rule_name,
                        exc,
                    )

                condition_type, required_count = _parse_condition_metadata(
                    condition_text,
                    plan.string_count or 0,
                )

                plan.condition_type = condition_type
                plan.required_count = required_count

                if plan.condition_ast is not None:
                    plan.required_strings = _required_strings_from_ast(plan.condition_ast)
                else:
                    # fallback to old behavior
                    plan.required_strings = _extract_required_strings(condition_text)

                plan.required_groups = _extract_required_groups(
                    plan.condition_ast,
                    plan.string_groups,
                    plan.groups,
                )

                logger.debug(
                    'Rule "%s" required strings=%s string_groups=%s',
                    match_rule_name,
                    sorted(plan.required_strings),
                    plan.string_groups,
                )

                logger.debug(
                    'Rule "%s" condition=%s required=%s total=%s',
                    match_rule_name,
                    plan.condition_type,
                    plan.required_count,
                    plan.string_count,
                )

    for rule_name, plan in rule_search_plans.items():
        logger.debug(
            'Plan "%s": condition=%s required=%s total=%s groups=%s',
            rule_name,
            plan.condition_type,
            plan.required_count,
            plan.string_count,
            [len(g) for g in plan.groups],
        )
    return rule_atoms, rule_content, rule_search_plans


def _yara_process_flags(current_rule: YaraRule, current_string: YaraString, flags: int):
    """Extract string modifiers from it's flags."""
    current_string.modifiers.clear()
    if flags & YaraStringFlagEnum.XOR:
        current_string.modifiers.append("xor")
    if flags & YaraStringFlagEnum.FULL_WORD:
        current_string.modifiers.append("fullword")
    if flags & YaraStringFlagEnum.WIDE:
        current_string.modifiers.append("wide")
    if flags & YaraStringFlagEnum.ASCII:
        current_string.modifiers.append("ascii")
    if flags & YaraStringFlagEnum.NO_CASE:
        current_string.modifiers.append("nocase")
    if flags >= (YaraStringFlagEnum.LAST_FLAG << 1):
        raise Exception(f"Unknown flags on {current_string.name} in {current_rule.name}")


def _yara_finish_string(current_rule: YaraRule, current_string: YaraString) -> tuple[YaraRule, YaraString]:
    """String is complete so add to rule."""
    if current_string:
        # if "nocase" string, yara must give us the atoms
        if "nocase" in current_string.modifiers and len(current_string.atoms) == 0:
            raise YaraStringNoAtomException(f"Yara did not output any atoms for nocase string {current_string.name}")

        current_rule.strings.append(current_string)
        current_string = None
    return current_rule, current_string


def yara_finish_rule(rules: list[YaraRule], current_rule: YaraRule, current_string: YaraString):
    """Rule is complete so add to rule list."""
    if current_rule is not None:
        _yara_finish_string(current_rule, current_string)
        rules.append(current_rule)
        current_rule = None


def _parse_yara_with_exe(yara_exe: str, rule_file: str) -> list[YaraRule]:
    """Run a dummy yara search with a yara exe patched to output atoms, and parse the result."""
    # FUTURE: add a timeout to this.
    # run patched yara
    process: subprocess.CompletedProcess[bytes]
    with tempfile.NamedTemporaryFile() as dummy_data_file:
        process = subprocess.run(  # noqa: S603  # nosec: B603
            (yara_exe, "--no-warnings", rule_file, dummy_data_file.name),
            capture_output=True,
        )  # noqa: S403  # nosec: B403
    if process.returncode != 0:
        raise Exception(f"Error running {yara_exe}, exit code {process.returncode}: {process.stderr.decode()}")

    current_rule: YaraRule = None
    current_string: YaraString = None
    rules: list[YaraRule] = []

    # parse the patched output
    for line in process.stdout.strip().split():
        if line.startswith(b"RULE:"):
            current_rule, current_string = _yara_finish_string(current_rule, current_string)
            if current_rule:
                rules.append(current_rule)
            current_rule = YaraRule()
            current_rule.name = line[5:].decode()
            current_rule.strings = []
        elif line.startswith(b"STRING:"):
            current_rule, current_string = _yara_finish_string(current_rule, current_string)
            current_string = YaraString()
            current_string.name = line[7:].decode()
            current_string.atoms = []
            current_string.modifiers = []
            current_string.re = []
        elif line.startswith(b"FLAGS:"):
            _yara_process_flags(current_rule, current_string, int(line[6:]))
        elif line.startswith(b"ATOM:"):
            atom = binascii.a2b_hex(line[5:])
            if len(atom) >= SEARCH_ATOM_SIZE_MIN:
                current_string.atoms.append(atom)
        elif line.startswith(b"RE:"):
            if len(current_string.re) > 0:
                raise Exception(
                    "Got another regular expression tree when one was already "
                    f"set for {current_string.name} in {current_rule.name}"
                )
            current_string.re = line[3:]
        else:
            raise Exception(f"Invalid identifier in yara output (line = {line})")
    yara_finish_rule(rules, current_rule, current_string)
    return rules


def _transform_searches(searches, transformer):
    """Run transformer function over list of searches."""
    transformed_searches = []
    for search in searches:
        new_search = []
        for elem in search:
            new_search.append(transformer(elem))
        transformed_searches.append(set(new_search))
    return transformed_searches


def _xor_transform(searches):
    """Xor keyword transform to expand out all single byte permutations."""
    new_searches = []
    for key in range(256):
        new_searches.extend(_transform_searches(searches, lambda elem, key=key: bytes(c ^ key for c in elem)))
    return new_searches


def _wide_transform(searches):
    """Wide keyword transform to convert ascii to Windows wide/utf16."""
    return _transform_searches(searches, lambda elem: b"\x00".join(bytes([c]) for c in elem) + b"\x00")


# FUTURE: most of this regex parsing code seems unnecessary, needs to be refactored.
class NodeTypeEnum:
    """Enum for type of regex node."""

    LEAF = 0
    AND = 1
    OR = 2


class AtomTreeNode:
    """Parsed RE tree node."""

    node_type: int
    # only set for non-leaf nodes
    children: list[AtomTreeNode]
    # only set for leaf node
    atom: bytes

    def __init__(self, node_type, atom=None):
        """Create a new node of `node_type` with the given children."""
        self.node_type = node_type
        self.children = list()
        self.atom = atom


def _parse_ast_call(node: ast.Call) -> AtomTreeNode:
    """Take python AST output for a function call and return equivalent AtomTreeNode.

    Should only be OR() or AND() calls.
    """
    if node.func.id == "OR":
        atom_node = AtomTreeNode(NodeTypeEnum.AND)
    elif node.func.id == "AND":
        atom_node = AtomTreeNode(NodeTypeEnum.OR)
    else:
        raise Exception("Invalid identifier in output (expected AND or OR)")

    for arg in node.args:
        if isinstance(arg, ast.Constant):
            binary_data = binascii.unhexlify(arg.value)
            atom_node.children.append(AtomTreeNode(NodeTypeEnum.LEAF, atom=binary_data))
        elif isinstance(arg, ast.Call):
            atom_node.children.append(_parse_ast_call(arg))
        else:
            raise Exception("Invalid argument (expected Str, Constant or Call)")

    return atom_node


def _parse_re_tree(tree_str: str) -> AtomTreeNode:
    """Use python's AST parser, to parse the RE compile output for the string."""
    re_tree_root: AtomTreeNode
    ast_tree: ast.Module = ast.parse(tree_str)
    ast_tree_root: ast.Call | ast.Constant = ast_tree.body[0].value

    if isinstance(ast_tree_root, ast.Call):
        re_tree_root = _parse_ast_call(ast_tree_root)
    elif isinstance(ast_tree_root, ast.Constant):
        re_tree_root = AtomTreeNode(NodeTypeEnum.LEAF, atom=binascii.unhexlify(ast_tree_root.value))
    else:
        raise Exception("Root of expression is not a call or constant")
    return re_tree_root


def _flatten(atom_tuple):
    """Merge all sets in a tuple from itertools.product together."""
    if not isinstance(atom_tuple, tuple):
        raise ValueError("flatten expects tuple from product")
    elements = []
    for child in atom_tuple:
        elements += list(child)
    return set(elements)


def _searches_from_node(node: AtomTreeNode) -> list[set]:
    """Return a list of sets where each set is a search.

    i.e. you would perform a lookup with all terms ANDed together
    inside each set, and each set ORed together.
    """
    if node.node_type == NodeTypeEnum.LEAF:
        return [set([node.atom])]

    result = []
    if node.node_type == NodeTypeEnum.OR:
        for child in node.children:
            result += _searches_from_node(child)
    elif node.node_type == NodeTypeEnum.AND:
        child_lists = []
        for child in node.children:
            child_lists.append(_searches_from_node(child))

        result = [_flatten(x) for x in list(product(*child_lists))]
    else:
        raise Exception("Bad node type")

    return result


def _remove_bad_atoms(searches):
    """Remove all small atoms from the searches.

    Returns a list of the new searches.
    This function ensures that each search is unique.
    """
    good_searches = set()
    for search in searches:
        # Need to use a frozenset so we can create a set of all these sets
        new_search = frozenset([term for term in search if len(term) >= SEARCH_ATOM_SIZE_MIN])
        good_searches.add(new_search)
    return list(good_searches)


def _get_minimal_atoms(searches):
    """Remove all searches which are a superset of another search.

    There's no point running a search which is more specific than an existing
    search since there will never be more results.
    """
    minimal_searches = []
    for search in searches:
        is_superset = False
        for other_search in searches:
            if other_search is not search and search.issuperset(other_search):
                is_superset = True
                break
        if not is_superset:
            minimal_searches.append(search)
    return minimal_searches


def _get_atoms_from_regex(tree_str: str, modifiers: list[str]) -> list[bytes]:
    """Get list of atoms from regex output from a run of patched yara."""
    # FUTURE: test characters in the tree string that could break parsing.
    # FUTURE: parsing the regex atoms as a tree is unnecessary.
    #         all we need is to grab out the atoms, check they're above the min ngram size,
    #         and get rid of any atoms that contain other atoms (same size or bigger).
    # FUTURE: make sure the above checks are being done for non-re strings.
    #         since they are exactly the same, the code should be combined.

    re_tree_root: AtomTreeNode = _parse_re_tree(tree_str)
    combo_set_list: list[set] = _searches_from_node(re_tree_root)
    removed_bad: frozenset[set] = _remove_bad_atoms(combo_set_list)
    searches: frozenset[set] = _get_minimal_atoms(removed_bad)

    if "wide" in modifiers:
        wide_searches = _wide_transform(searches)
        if "ascii" in modifiers:
            searches.extend(wide_searches)
        else:
            searches = wide_searches

    if "xor" in modifiers:
        searches = _xor_transform(searches)

    atoms: list[bytes] = []
    for atom_set in searches:
        for atom in atom_set:
            atoms.append(atom)
    return atoms
