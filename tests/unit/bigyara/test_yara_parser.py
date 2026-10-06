import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock

from azul_plugin_retrohunt.bigyara import SEARCH_ATOM_SIZE_MIN
from azul_plugin_retrohunt.bigyara import yara_parse
from azul_plugin_retrohunt.bigyara.yara_parse import (
    YaraRule,
    YaraString,
    _parse_yara_with_exe,
)

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


def _yara_x_executable() -> str:
    """Return the YARA-X binary shipped beside the plugin package."""
    return os.path.join(
        os.path.dirname(os.path.dirname(yara_parse.__file__)),
        "yr",
    )


def parse_yara(rule_text: str) -> list[YaraRule]:
    """Run the YARA-X debug-atoms parser against a temporary source file."""
    with tempfile.NamedTemporaryFile(
        suffix=".yar",
        mode="w",
        delete=False,
    ) as yara_file:
        yara_file.write(rule_text)
        tmp_path = yara_file.name

    try:
        return _parse_yara_with_exe(
            _yara_x_executable(),
            tmp_path,
        )
    finally:
        os.remove(tmp_path)


class TestYaraParser(unittest.TestCase):
    def assert_yara_x_string(
        self,
        string: YaraString,
        expected_name: str,
        *,
        require_atom: bool = False,
    ):
        """Validate the representation returned by `yr debug atoms`."""
        self.assertEqual(string.name, expected_name)

        if require_atom:
            self.assertTrue(string.atoms)

        self.assertTrue(all(isinstance(atom, bytes) and len(atom) >= SEARCH_ATOM_SIZE_MIN for atom in string.atoms))

        # The YARA-X debug command returns final matcher atoms only. It does
        # not expose classic YARA FLAGS or RE-tree output.
        self.assertEqual(string.modifiers, [])
        self.assertEqual(string.re, b"")

    def test_yara_parse1(self):
        """Parse a simple anonymous ASCII/wide string with YARA-X."""
        yara_rules: list[YaraRule] = parse_yara(TEST_RULE_1)
        self.assertEqual(len(yara_rules), 1)

        rule = yara_rules[0]
        self.assertEqual(rule.name, "weak_test")
        self.assertEqual(len(rule.strings), 1)

        self.assert_yara_x_string(
            rule.strings[0],
            "$",
            require_atom=True,
        )

    def test_yara_parse2(self):
        """Parse hex and ASCII/wide strings with YARA-X."""
        yara_rules: list[YaraRule] = parse_yara(TEST_RULE_2)
        self.assertEqual(len(yara_rules), 1)

        rule = yara_rules[0]
        self.assertEqual(rule.name, "weak_test_2")
        self.assertEqual(len(rule.strings), 2)

        self.assert_yara_x_string(
            rule.strings[0],
            "$foo",
        )
        self.assert_yara_x_string(
            rule.strings[1],
            "$bar",
            require_atom=True,
        )

    def test_yara_parse3(self):
        """Parse mixed hex and ASCII/wide strings with YARA-X."""
        yara_rules: list[YaraRule] = parse_yara(TEST_RULE_3)
        self.assertEqual(len(yara_rules), 1)

        rule = yara_rules[0]
        self.assertEqual(rule.name, "weak_test_3")
        self.assertEqual(len(rule.strings), 3)

        self.assert_yara_x_string(
            rule.strings[0],
            "$foo",
        )
        self.assert_yara_x_string(
            rule.strings[1],
            "$baz",
            require_atom=True,
        )
        self.assert_yara_x_string(
            rule.strings[2],
            "$bar",
            require_atom=True,
        )

    def test_yara_parse_nibble(self):
        """Nibble wildcards are accepted even if no usable matcher atom remains."""
        yara_rules: list[YaraRule] = parse_yara(TEST_RULE_NIBBLE)
        self.assertEqual(len(yara_rules), 1)

        rule = yara_rules[0]
        self.assertEqual(rule.name, "weak_test_nibble")
        self.assertEqual(len(rule.strings), 1)

        self.assert_yara_x_string(
            rule.strings[0],
            "$nibble",
        )

    @mock.patch("azul_plugin_retrohunt.bigyara.yara_parse.subprocess.run")
    def test_yara_x_output_parser(self, run_mock):
        """Parse JSON output from `yr debug atoms --json`."""

        run_mock.return_value = subprocess.CompletedProcess(
            args=("/fake/yr", "debug", "atoms", "--json", "/tmp/rule.yar"),
            returncode=0,
            stdout=(
                b"""[
                    {
                        "rule": "test",
                        "pattern": "$a",
                        "atoms": ["41424344"]
                    },
                    {
                        "rule": "test",
                        "pattern": "$b",
                        "atoms": ["01020304", "01020305"]
                    }
                ]"""
            ),
            stderr=b"",
        )

        rules = _parse_yara_with_exe(
            "/fake/yr",
            "/tmp/rule.yar",
        )

        run_mock.assert_called_once_with(
            (
                "/fake/yr",
                "debug",
                "atoms",
                "--json",
                "/tmp/rule.yar",
            ),
            capture_output=True,
        )

        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].name, "test")
        self.assertEqual(len(rules[0].strings), 2)

        self.assertEqual(rules[0].strings[0].name, "$a")
        self.assertEqual(
            rules[0].strings[0].atoms,
            [b"ABCD"],
        )

        self.assertEqual(rules[0].strings[1].name, "$b")
        self.assertEqual(
            rules[0].strings[1].atoms,
            [
                b"\x01\x02\x03\x04",
                b"\x01\x02\x03\x05",
            ],
        )

    @mock.patch("azul_plugin_retrohunt.bigyara.yara_parse.subprocess.run")
    def test_yara_x_output_filters_short_atoms(self, run_mock):
        """Atoms below Retrohunt's configured minimum n-gram size are ignored."""

        self.assertGreater(SEARCH_ATOM_SIZE_MIN, 1)

        short_atom = b"A" * (SEARCH_ATOM_SIZE_MIN - 1)
        good_atom = b"B" * SEARCH_ATOM_SIZE_MIN

        run_mock.return_value = subprocess.CompletedProcess(
            args=("/fake/yr", "debug", "atoms", "--json", "/tmp/rule.yar"),
            returncode=0,
            stdout=f"""
            [
                {{
                    "rule": "test",
                    "pattern": "$a",
                    "atoms": [
                        "{short_atom.hex().upper()}",
                        "{good_atom.hex().upper()}"
                    ]
                }}
            ]
            """.encode(),
            stderr=b"",
        )

        rules = _parse_yara_with_exe(
            "/fake/yr",
            "/tmp/rule.yar",
        )

        self.assertEqual(
            rules[0].strings[0].atoms,
            [good_atom],
        )

    @mock.patch("azul_plugin_retrohunt.bigyara.yara_parse.subprocess.run")
    def test_yara_x_output_keeps_string_without_usable_atoms(
        self,
        run_mock,
    ):
        """A valid YARA-X string may remain present with no usable broad atom."""

        self.assertGreater(SEARCH_ATOM_SIZE_MIN, 1)

        short_atom = b"A" * (SEARCH_ATOM_SIZE_MIN - 1)
        good_atom = b"B" * SEARCH_ATOM_SIZE_MIN

        run_mock.return_value = subprocess.CompletedProcess(
            args=("/fake/yr", "debug", "atoms", "--json", "/tmp/rule.yar"),
            returncode=0,
            stdout=f"""
            [
                {{
                    "rule": "test",
                    "pattern": "$short",
                    "atoms": ["{short_atom.hex().upper()}"]
                }},
                {{
                    "rule": "test",
                    "pattern": "$good",
                    "atoms": ["{good_atom.hex().upper()}"]
                }}
            ]
            """.encode(),
            stderr=b"",
        )

        rules = _parse_yara_with_exe(
            "/fake/yr",
            "/tmp/rule.yar",
        )

        self.assertEqual(len(rules[0].strings), 2)

        self.assertEqual(rules[0].strings[0].name, "$short")
        self.assertEqual(rules[0].strings[0].atoms, [])

        self.assertEqual(rules[0].strings[1].name, "$good")
        self.assertEqual(
            rules[0].strings[1].atoms,
            [good_atom],
        )

    @mock.patch("azul_plugin_retrohunt.bigyara.yara_parse.subprocess.run")
    def test_yara_x_error_is_reported(self, run_mock):
        """A failed `yr debug atoms` invocation must fail atom parsing."""
        run_mock.return_value = subprocess.CompletedProcess(
            args=("/fake/yr", "debug", "atoms", "/tmp/rule.yar"),
            returncode=1,
            stdout=b"",
            stderr=b"compile error",
        )

        with self.assertRaisesRegex(
            Exception,
            "Error running /fake/yr, exit code 1: compile error",
        ):
            _parse_yara_with_exe(
                "/fake/yr",
                "/tmp/rule.yar",
            )

    @mock.patch("azul_plugin_retrohunt.bigyara.yara_parse.subprocess.run")
    def test_yara_x_json_merges_duplicate_named_patterns(
        self,
        run_mock,
    ):
        """Repeated entries for a named pattern merge; anonymous patterns stay distinct."""

        run_mock.return_value = subprocess.CompletedProcess(
            args=("/fake/yr", "debug", "atoms", "--json", "/tmp/rule.yar"),
            returncode=0,
            stdout=b"""
            [
                {
                    "rule": "test",
                    "pattern": "$a",
                    "atoms": ["41424344"]
                },
                {
                    "rule": "test",
                    "pattern": "$a",
                    "atoms": ["45464748"]
                }
            ]
            """,
            stderr=b"",
        )

        rules = _parse_yara_with_exe(
            "/fake/yr",
            "/tmp/rule.yar",
        )

        self.assertEqual(len(rules), 1)
        self.assertEqual(len(rules[0].strings), 1)

        self.assertEqual(
            rules[0].strings[0].atoms,
            [
                b"ABCD",
                b"EFGH",
            ],
        )

    def parse_json_output(self, output):
        """Exercise the JSON decoder with a successful CLI response."""
        with mock.patch.object(yara_parse.subprocess, "run") as run_mock:
            run_mock.return_value = subprocess.CompletedProcess(
                args=("/fake/yr", "debug", "atoms", "--json", "/tmp/rule.yar"),
                returncode=0,
                stdout=json.dumps(output).encode(),
                stderr=b"",
            )
            return _parse_yara_with_exe("/fake/yr", "/tmp/rule.yar")

    def test_yara_x_json_preserves_multiple_anonymous_patterns(self):
        """Each anonymous JSON entry represents a distinct declared string."""
        atoms = [b"A" * SEARCH_ATOM_SIZE_MIN, b"B" * SEARCH_ATOM_SIZE_MIN]
        rules = self.parse_json_output(
            [
                {"rule": "anonymous", "pattern": "$", "atoms": [atoms[0].hex()]},
                {"rule": "anonymous", "pattern": "$", "atoms": [atoms[1].hex()]},
                {"rule": "anonymous", "pattern": "$", "atoms": []},
            ]
        )
        self.assertEqual(len(rules), 1)
        self.assertEqual([string.name for string in rules[0].strings], ["$", "$", "$"])
        self.assertEqual([string.atoms for string in rules[0].strings], [[atoms[0]], [atoms[1]], []])

    def test_yara_x_json_retains_explicit_empty_atom_list(self):
        """An explicit zero-atom pattern must not disappear from the rule."""
        rules = self.parse_json_output(
            [
                {"rule": "fixed", "pattern": "$header", "atoms": []},
            ]
        )
        self.assertEqual(len(rules), 1)
        self.assertEqual(len(rules[0].strings), 1)
        self.assert_yara_x_string(rules[0].strings[0], "$header")
        self.assertEqual(rules[0].strings[0].atoms, [])

    def test_yara_x_json_deduplicates_atoms_within_and_across_entries(self):
        """Named-pattern atoms remain unique in their first-seen order."""
        first = b"A" * SEARCH_ATOM_SIZE_MIN
        second = b"B" * SEARCH_ATOM_SIZE_MIN
        rules = self.parse_json_output(
            [
                {"rule": "test", "pattern": "$a", "atoms": [first.hex(), first.hex()]},
                {"rule": "test", "pattern": "$a", "atoms": [first.hex(), second.hex(), second.hex()]},
            ]
        )
        self.assertEqual(len(rules[0].strings), 1)
        self.assertEqual(rules[0].strings[0].atoms, [first, second])

    def test_yara_x_json_same_pattern_name_in_different_rules(self):
        """Pattern-name lookup tables must be isolated by rule."""
        first = b"A" * SEARCH_ATOM_SIZE_MIN
        second = b"B" * SEARCH_ATOM_SIZE_MIN
        rules = self.parse_json_output(
            [
                {"rule": "first", "pattern": "$a", "atoms": [first.hex()]},
                {"rule": "second", "pattern": "$a", "atoms": [second.hex()]},
                {"rule": "first", "pattern": "$a", "atoms": [first.hex()]},
            ]
        )
        by_name = {rule.name: rule for rule in rules}
        self.assertEqual(set(by_name), {"first", "second"})
        for name, atom in [("first", first), ("second", second)]:
            self.assertEqual(len(by_name[name].strings), 1)
            self.assertEqual(by_name[name].strings[0].name, "$a")
            self.assertEqual(by_name[name].strings[0].atoms, [atom])

    @mock.patch("azul_plugin_retrohunt.bigyara.yara_parse.subprocess.run")
    def test_yara_x_malformed_json_is_reported(self, run_mock):
        """Malformed JSON must fail parsing rather than produce an empty result."""
        run_mock.return_value = subprocess.CompletedProcess(
            args=(),
            returncode=0,
            stdout=b"not JSON",
            stderr=b"",
        )
        with self.assertRaises(json.JSONDecodeError):
            _parse_yara_with_exe("/fake/yr", "/tmp/rule.yar")

    def test_yara_x_non_list_json_is_rejected(self):
        """Successful CLI output must have the expected top-level list shape."""
        for value in [{}, None, "unexpected", 42]:
            with self.subTest(value=value):
                with self.assertRaisesRegex(Exception, "Unexpected YARA-X JSON format: expected list"):
                    self.parse_json_output(value)

    def test_yara_x_invalid_hex_is_warned_and_skipped(self):
        """Invalid atoms must not discard valid atoms from the same pattern."""
        good = b"A" * SEARCH_ATOM_SIZE_MIN
        with self.assertLogs(yara_parse.logger, level="WARNING") as logs:
            rules = self.parse_json_output(
                [
                    {"rule": "test", "pattern": "$a", "atoms": ["ZZZZ", "123", good.hex()]},
                ]
            )
        self.assertEqual(rules[0].strings[0].atoms, [good])
        self.assertEqual(len(logs.records), 2)
        self.assertTrue(all("Invalid atom returned from YARA-X" in record.getMessage() for record in logs.records))

    def test_yara_x_real_anonymous_patterns_remain_distinct(self):
        """The shipped CLI and decoder must preserve all anonymous declarations."""
        rules = parse_yara("""
        rule Anonymous {
            strings:
                $ = "ALPHA_ONE"
                $ = "BRAVO_TWO"
                $ = "CHARLIE_THREE"
            condition: 2 of them
        }
        """)
        self.assertEqual(len(rules), 1)
        self.assertEqual(len(rules[0].strings), 3)
        for string in rules[0].strings:
            self.assert_yara_x_string(string, "$", require_atom=True)
        self.assertEqual(len({frozenset(string.atoms) for string in rules[0].strings}), 3)

    def test_yara_x_real_fixed_offset_keeps_zero_atom_pattern(self):
        """The shipped CLI emits a fixed-offset pattern even without matcher atoms."""
        rules = parse_yara("""
        rule FixedOffset {
            strings: $header = "HEADER_TOKEN"
            condition: $header at 0
        }
        """)
        self.assertEqual(len(rules), 1)
        self.assertEqual(len(rules[0].strings), 1)
        self.assert_yara_x_string(rules[0].strings[0], "$header")
        self.assertEqual(rules[0].strings[0].atoms, [])
