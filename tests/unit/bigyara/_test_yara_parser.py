import os
import subprocess
import tempfile
from unittest import mock

from azul_plugin_retrohunt import test_utils
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


class TestYaraParser(test_utils.BaseIngestorIndexerTest):
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
        """Parse the indentation-based `yr debug atoms` output."""
        run_mock.return_value = subprocess.CompletedProcess(
            args=("/fake/yr", "debug", "atoms", "/tmp/rule.yar"),
            returncode=0,
            stdout=(b"rule test\n  $a\n    41424344\n  $b\n    01020304\n    01020305\n"),
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
            args=("/fake/yr", "debug", "atoms", "/tmp/rule.yar"),
            returncode=0,
            stdout=(
                b"rule test\n"
                b"  $a\n" + f"    {short_atom.hex().upper()}\n".encode() + f"    {good_atom.hex().upper()}\n".encode()
            ),
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
            args=("/fake/yr", "debug", "atoms", "/tmp/rule.yar"),
            returncode=0,
            stdout=(
                b"rule test\n"
                b"  $short\n"
                + f"    {short_atom.hex().upper()}\n".encode()
                + b"  $good\n"
                + f"    {good_atom.hex().upper()}\n".encode()
            ),
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
