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


# these are redefined aliases from the search module to avoid circular dependency
RuleFileMatches = dict[str, list[str]]
RuleAtoms = dict[str, list[bytes]]
RuleContent = dict[str, bytes]


def parse_yara_rules(rule_text: str, progress_callback: ProgressCallback) -> tuple[RuleAtoms, RuleContent]:
    """Compile the yara rule, parsing out search atoms.

    Will parse the yara rule with small atoms first to determine
    whether there are any nocase strings. If there are, we'll have to stick
    with small atoms, otherwise we can use the large atom version
    """
    yara_rules: list[YaraRule]
    rule_atoms: RuleAtoms = {}

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
        for yara_string in yara_rules[rule_index].strings:
            if "nocase" not in yara_string.modifiers and len(yara_string.re) > 0:
                # If it is nocase or a normal string, the searches are the atoms
                # if it is a regular expression, pull the searches from the RE tree
                # FUTURE: this function does a heap of unnecessary work and needs to be refactored.
                yara_string.atoms = _get_atoms_from_regex(yara_string.re, yara_string.modifiers)

            if len(yara_string.atoms) == 0:
                raise YaraStringNoAtomException(
                    f"Failed to find any valid atoms for string {yara_string.name} in {yara_rules[rule_index].name}"
                )

            for yara_atom in yara_string.atoms:
                if yara_atom not in new_atoms:
                    new_atoms.append(yara_atom)
        progress_callback(
            SearchPhaseEnum.ATOM_PARSE,
            rule_index + 1,
            len(yara_rules),
            (yara_rules[rule_index].name, new_atoms),
        )
        rule_atoms[yara_rules[rule_index].name] = new_atoms

        logger.info(f'Found {len(rule_atoms[yara_rules[rule_index].name])} atoms for "{yara_rules[rule_index].name}"')

    rule_content: RuleContent = {}
    condition_re = re.compile(r"rule (.+?)(?:\:.+?)?{.+?condition:(.+?)}", re.DOTALL)
    for match in re.finditer(condition_re, rule_text):
        re_rule_name = match.group(1).strip()
        for match_rule_name in rule_atoms:
            if match_rule_name == re_rule_name:
                rule_content[match_rule_name] = match.group(0)

    return rule_atoms, rule_content


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
