"""Functions for extracting terms from snort rules."""

# import binascii
import logging

# from . import SEARCH_ATOM_SIZE_MIN, ProgressCallback, SearchPhaseEnum
from . import ProgressCallback

# import re
# import sre_constants
# import sre_parse
# from io import StringIO

# from idstools import rule as snortparse


# these are redefined from the search module to avoid circular dependency
RuleAtoms = dict[str, list[bytes]]
RuleContent = dict[str, bytes]


logger = logging.getLogger("bigyara.snort_atom_parser")


def parse_suricata_rules(rule_text: str, progress_callback: ProgressCallback) -> tuple[RuleAtoms, RuleContent]:
    """Return searchable atoms and list of rule text out of the string of all suricata rules."""
    # FUTURE suricata - implement
    raise NotImplementedError("Suricata parsing is not implemented.")
    # rule_atoms: RuleAtoms = {}
    # rule_content: RuleContent = {}

    # parsed_rules: list[dict] = snortparse.parse_fileobj(StringIO(rule_text))

    # progress_callback(SearchPhaseEnum.ATOM_PARSE, 0, len(parsed_rules), None)

    # for rule_index in range(len(parsed_rules)):
    #     new_atoms: list[bytes] = []
    #     rule_name = f"{parsed_rules[rule_index]['sid']}:{parsed_rules[rule_index]['msg']}"
    #     for atom in _atoms_for_rule(parsed_rules[rule_index]):
    #         if atom not in new_atoms:
    #             new_atoms.append(atom)

    #     progress_callback(SearchPhaseEnum.ATOM_PARSE, rule_index + 1, len(parsed_rules), (rule_name, new_atoms))

    #     if len(new_atoms) > 0:
    #         rule_atoms[rule_name] = new_atoms
    #         rule_content[rule_name] = parsed_rules[rule_index]["raw"]

    # return rule_atoms, rule_content


# def _atoms_for_rule(rule):
#     """Given a snort rule parsed by idstools, return the set of atom strings used by the rule.

#     Note: Lots of unsupported combinations, options, etc.
#     """
#     atoms = []
#     for option in rule["options"]:
#         value = option.get("value", "")
#         if option["name"] in ("content", "pcre"):
#             if value.startswith("!"):
#                 logger.warning("Match negation is not currently supported.")
#                 continue
#             if value[0] != '"' or value[-1] != '"':
#                 raise Exception("Missing quotes in content/pcre rule.")
#         if option["name"] == "content":
#             atom = _handle_escapes(value[1:-1])
#             # make sure the atom meets biggrep's requirement for size.
#             if len(atom) >= 3:
#                 atoms.append(atom)
#         elif option["name"] == "pcre":
#             atoms += _pcre_atoms(value[1:-1])
#         elif option["name"] == "nocase":
#             logger.warning("'nocase' not supported. Only searching for case-sensitive version.")
#     atoms += _ips_to_atoms(rule["header"])
#     return atoms


# def _ips_to_atoms(header: str) -> list[bytes]:
#     """Convert any rule ip addresses to network bytes.

#     Note: Does not handle cidr notation.
#     """
#     atoms: list[bytes] = []
#     for match in re.finditer(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})", header):
#         buffer = bytes(
#             [
#                 int(match.group(1)),
#                 int(match.group(2)),
#                 int(match.group(3)),
#                 int(match.group(4)),
#             ]
#         )
#         atoms.append(buffer)
#     return atoms


# def _handle_escapes(string: str) -> bytes:
#     """Expand out a content option to transform any escaped hex sequences."""
#     # unescape special chars
#     string = string.replace("\\\\", "\\").replace('\\"', '"').replace("\\;", ";")
#     # hex escapes (upper/lower with/without whitespaces)
#     a = re.sub(
#         b"\\|([a-fA-F0-9 ]+)\\|",
#         lambda x: binascii.unhexlify(x.group(1).replace(b" ", b"").lower()),
#         string.encode("utf-8"),
#     )

#     return a


# def _pcre_atoms(s):
#     """Parse any pcre regexes and find their literal strings (gte 3 bytes).

#     Note: No effort to handle booelan or nested pattern logic yet.
#     """
#     buf = b""
#     literals = []
#     flags = 0
#     if s.startswith("/"):
#         # try and map flags to python equivs
#         for f in s[s.rindex("/") :]:
#             if f == "a":
#                 flags |= re.ASCII
#             elif f == "i":
#                 logger.warning("pcre contains ignore case flag, this is not supported")
#                 flags |= re.IGNORECASE
#             elif f == "m":
#                 flags |= re.MULTILINE
#             elif f == "s":
#                 flags |= re.DOTALL
#             # unicode default/redundant in python
#         s = s[1 : s.rindex("/")]

#     for typ, val in sre_parse.parse(s, flags=flags):
#         if typ == sre_constants.LITERAL:
#             buf += bytes([val])
#         else:
#             if len(buf) >= SEARCH_ATOM_SIZE_MIN:
#                 literals.append(buf)
#             buf = b""
#     if len(buf) >= SEARCH_ATOM_SIZE_MIN:
#         literals.append(buf)
#     return literals
