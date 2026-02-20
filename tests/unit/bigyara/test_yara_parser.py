import os
import tempfile
import unittest

from azul_plugin_retrohunt.bigyara.env import executables
from azul_plugin_retrohunt.bigyara.yara_parse import YaraRule, YaraString, _get_atoms_from_regex, _parse_yara_with_exe

TEST_RULE_1 = """
rule weak_test {
    meta:
        poc = "azul@asd.gov.au"
        description = "Test rule"

    strings:
        $ = "DEFGHIJ" ascii wide
    condition:
        all of them
}
"""


TEST_RULE_2 = """
rule weak_test_2 {
    meta:
        poc = "azul@asd.gov.au"
        description = "Test rule"

    strings:
        $foo = { 44 45 46 47 ?? 49 4A }
        $bar = "ABCD" wide ascii
    condition:
        2 of them
}
"""


TEST_RULE_3 = """
rule weak_test_3 {
    meta:
        poc = "azul@asd.gov.au"
        description = "Test rule"

    strings:
        $foo = { AA ?? 44 45 46 47 [2] 49 ?? }
        $baz = { AA 44 45 46 47 }
        $bar = "ABCD" wide ascii
    condition:
        (uint16(0) == 0xAA) and all of them
        and filesize < 1MB
}
"""

TEST_RULE_NIBBLE = """
rule weak_test_nibble {
    meta:
        poc = "azul@asd.gov.au"
        description = "Test rule"

    strings:
        $nibble = { 11 22 3? 44 55 ?6 77 88 }
    condition:
        $nibble
}
"""


TEST_RULE_NIBBLE = """
rule weak_test_nibble {
    meta:
        poc = "azul@asd.gov.au"
        description = "Test rule"

    strings:
        $nibble = { 11 22 3? 44 55 ?6 77 88 }
    condition:
        $nibble
}
"""


def parse_yara(rule_text: str) -> list[YaraRule]:
    """This is a simplified version of yara_parse.parse_yara_rules() that only returns the YaraRules."""
    # write the yara rules to a file
    with tempfile.NamedTemporaryFile(suffix=".yar", mode="w", delete=False) as yara_file:
        yara_file.write(rule_text)
        tmp_path = yara_file.name

    yara_rules = _parse_yara_with_exe(executables["yarac-large"], tmp_path)

    # delete the yara rule file
    os.remove(tmp_path)

    return yara_rules


class TestYaraParser(unittest.TestCase):
    def test_yara_parse1(self):
        """Basic rule parsing."""

        yara_rules: list[YaraRule] = parse_yara(TEST_RULE_1)
        self.assertEqual(len(yara_rules), 1)

        rule = yara_rules[0]
        self.assertEqual(rule.name, "weak_test")
        self.assertEqual(len(rule.strings), 1)

        string: YaraString = rule.strings[0]
        self.assertEqual(string.name, "$")
        self.assertEqual(string.atoms, [b"DEFGHIJ", b"D\x00E\x00F\x00G\x00H\x00I\x00J\x00"])
        self.assertEqual(string.modifiers, ["wide", "ascii"])
        self.assertEqual(string.re, [])

    def test_yara_parse2(self):
        """Basic rule parsing."""
        yara_rules: list[YaraRule] = parse_yara(TEST_RULE_2)
        self.assertEqual(len(yara_rules), 1)

        rule = yara_rules[0]
        self.assertEqual(rule.name, "weak_test_2")
        self.assertEqual(len(rule.strings), 2)

        string: YaraString = rule.strings[0]
        self.assertEqual(string.name, "$foo")
        self.assertEqual(string.atoms, [])
        self.assertEqual(string.re, b'OR("44454647","494A")')
        self.assertEqual(string.modifiers, ["ascii"])

        string: YaraString = rule.strings[1]
        self.assertEqual(string.name, "$bar")
        self.assertEqual(string.atoms, [b"ABCD", b"A\x00B\x00C\x00D\x00"])
        self.assertEqual(string.modifiers, ["wide", "ascii"])
        self.assertEqual(string.re, [])

    def test_yara_parse3(self):
        """Basic rule parsing."""
        yara_rules: list[YaraRule] = parse_yara(TEST_RULE_3)
        self.assertEqual(len(yara_rules), 1)

        rule = yara_rules[0]
        self.assertEqual(rule.name, "weak_test_3")
        self.assertEqual(len(rule.strings), 3)

        string: YaraString = rule.strings[0]
        self.assertEqual(string.name, "$foo")
        self.assertEqual(string.atoms, [])
        self.assertEqual(string.modifiers, ["ascii"])
        self.assertEqual(string.re, b'OR("AA","44454647","49")')

        string: YaraString = rule.strings[1]
        self.assertEqual(string.name, "$baz")
        self.assertEqual(string.atoms, [b"\xaaDEFG"])
        self.assertEqual(string.modifiers, ["ascii"])
        self.assertEqual(string.re, [])

        string: YaraString = rule.strings[2]
        self.assertEqual(string.name, "$bar")
        self.assertEqual(string.atoms, [b"ABCD", b"A\x00B\x00C\x00D\x00"])
        self.assertEqual(string.modifiers, ["wide", "ascii"])
        self.assertEqual(string.re, [])

    def test_yara_parse_nibble(self):
        """Basic rule parsing."""
        yara_rules: list[YaraRule] = parse_yara(TEST_RULE_NIBBLE)
        self.assertEqual(len(yara_rules), 1)
        rule = yara_rules[0]
        self.assertEqual(rule.name, "weak_test_nibble")
        self.assertEqual(len(rule.strings), 1)

        string = rule.strings[0]
        self.assertEqual(string.name, "$nibble")
        self.assertEqual(string.atoms, [])
        self.assertEqual(string.re, b'OR("1122","4455","7788")')
        self.assertEqual(string.modifiers, ["ascii"])

    def test_re_parser(self):
        """Parse the re AST from rules."""
        atoms: list[bytes] = _get_atoms_from_regex(b'"44454647"', "ascii")
        self.assertEqual(len(atoms), 1)
        self.assertEqual(atoms[0], b"DEFG")

    def _test_re_parser_wildcards(self):
        """Parse the re AST from rules."""
        atoms: list[bytes] = _get_atoms_from_regex(b'OR("AA","44454647","49")', "ascii")
        self.assertEqual(len(atoms), 1)
        self.assertEqual(atoms[0], b"DEFG")

    def _test_re_parser_wide(self):
        """Parse the re AST from rules."""
        atoms: list[bytes] = _get_atoms_from_regex(b'OR("AA","44454647","49")', "wide")
        self.assertEqual(len(atoms), 1)
        self.assertEqual(atoms[0], b"D\x00E\x00F\x00G\x00")

    def _test_re_parser_xor(self):
        """Parse the re AST from rules."""
        atoms: list[bytes] = _get_atoms_from_regex(b'OR("AA","44454647","49")', "xor")
        self.assertEqual(len(atoms), 256)
        self.assertEqual(atoms[0] == b"DEFG")
        self.assertEqual(atoms[1] == b"EDGF")
        self.assertEqual(atoms[255] == b"\xbb\xba\xb9\xb8")
