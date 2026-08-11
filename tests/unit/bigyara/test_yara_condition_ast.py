"""Unit tests for the current YARA condition AST and search-plan logic."""

import unittest
from unittest import mock

from azul_plugin_retrohunt.bigyara import yara_parse
from azul_plugin_retrohunt.bigyara.yara_parse import (
    AndNode,
    NOfNode,
    OrNode,
    StringNode,
    UnknownNode,
    _build_condition_ast,
    _evaluate_condition_ast,
    _extract_required_groups,
    _extract_required_strings,
    _parse_condition_metadata,
    _required_strings_from_ast,
    parse_yara_rules,
)


class ConditionAstTestCase(unittest.TestCase):
    """Common helpers for condition AST tests."""

    string_names = {"$a", "$b", "$c", "$d"}

    def build_ast(self, condition: str):
        """Build an AST using the standard test string names."""
        condition_ast = _build_condition_ast(condition, self.string_names)
        self.assertIsNotNone(condition_ast)
        return condition_ast


class TestConditionAstParsing(ConditionAstTestCase):
    """Verify condition parsing, precedence, masking, and special syntax."""

    def test_and_expression(self):
        self.assertEqual(
            self.build_ast("$a and $b"),
            AndNode(
                children=[
                    StringNode("$a"),
                    StringNode("$b"),
                ]
            ),
        )

    def test_or_expression(self):
        self.assertEqual(
            self.build_ast("$a or $b"),
            OrNode(
                children=[
                    StringNode("$a"),
                    StringNode("$b"),
                ]
            ),
        )

    def test_and_has_higher_precedence_than_or(self):
        self.assertEqual(
            self.build_ast("$a or $b and $c"),
            OrNode(
                children=[
                    StringNode("$a"),
                    AndNode(
                        children=[
                            StringNode("$b"),
                            StringNode("$c"),
                        ]
                    ),
                ]
            ),
        )

    def test_parentheses_override_precedence(self):
        self.assertEqual(
            self.build_ast("($a or $b) and $c"),
            AndNode(
                children=[
                    OrNode(
                        children=[
                            StringNode("$a"),
                            StringNode("$b"),
                        ]
                    ),
                    StringNode("$c"),
                ]
            ),
        )

    def test_nested_and_nodes_are_flattened(self):
        self.assertEqual(
            self.build_ast("$a and $b and $c"),
            AndNode(
                children=[
                    StringNode("$a"),
                    StringNode("$b"),
                    StringNode("$c"),
                ]
            ),
        )

    def test_nested_or_nodes_are_flattened(self):
        self.assertEqual(
            self.build_ast("$a or $b or $c"),
            OrNode(
                children=[
                    StringNode("$a"),
                    StringNode("$b"),
                    StringNode("$c"),
                ]
            ),
        )

    def test_any_of_them_becomes_or(self):
        self.assertEqual(
            self.build_ast("any of them"),
            OrNode(
                children=[
                    StringNode("$a"),
                    StringNode("$b"),
                    StringNode("$c"),
                    StringNode("$d"),
                ]
            ),
        )

    def test_all_of_them_becomes_and(self):
        self.assertEqual(
            self.build_ast("all of them"),
            AndNode(
                children=[
                    StringNode("$a"),
                    StringNode("$b"),
                    StringNode("$c"),
                    StringNode("$d"),
                ]
            ),
        )

    def test_n_of_them_becomes_n_of_node(self):
        self.assertEqual(
            self.build_ast("2 of them"),
            NOfNode(
                required=2,
                children=[
                    StringNode("$a"),
                    StringNode("$b"),
                    StringNode("$c"),
                    StringNode("$d"),
                ],
            ),
        )

    def test_explicit_string_list(self):
        self.assertEqual(
            self.build_ast("all of ($a, $c)"),
            AndNode(
                children=[
                    StringNode("$a"),
                    StringNode("$c"),
                ]
            ),
        )

    def test_wildcard_string_list(self):
        condition_ast = _build_condition_ast(
            "all of ($prefix*)",
            {"$prefix_one", "$prefix_two", "$unrelated"},
        )

        self.assertEqual(
            condition_ast,
            AndNode(
                children=[
                    StringNode("$prefix_one"),
                    StringNode("$prefix_two"),
                ]
            ),
        )

    def test_unsupported_predicate_becomes_unknown(self):
        self.assertEqual(
            self.build_ast("filesize > 5MB"),
            UnknownNode(raw_text="filesize > 5MB"),
        )

    def test_unknown_and_string_are_retained(self):
        self.assertEqual(
            self.build_ast("filesize > 5MB and $a"),
            AndNode(
                children=[
                    UnknownNode(raw_text="filesize > 5MB"),
                    StringNode("$a"),
                ]
            ),
        )

    def test_unknown_or_string_are_retained(self):
        self.assertEqual(
            self.build_ast("filesize > 5MB or $a"),
            OrNode(
                children=[
                    UnknownNode(raw_text="filesize > 5MB"),
                    StringNode("$a"),
                ]
            ),
        )

    def test_boolean_words_inside_quoted_string_are_not_split(self):
        self.assertEqual(
            self.build_ast('pe.imphash() == "one and two or three" and $a'),
            AndNode(
                children=[
                    UnknownNode(raw_text='pe.imphash() == "one and two or three"'),
                    StringNode("$a"),
                ]
            ),
        )

    def test_boolean_words_inside_regex_are_not_split(self):
        self.assertEqual(
            self.build_ast("filename matches /one and two or three/ and $a"),
            AndNode(
                children=[
                    UnknownNode(raw_text="filename matches /one and two or three/"),
                    StringNode("$a"),
                ]
            ),
        )

    def test_boolean_words_inside_block_comment_are_ignored(self):
        self.assertEqual(
            self.build_ast("$a /* or $b and $d */ and $c"),
            AndNode(
                children=[
                    StringNode("$a"),
                    StringNode("$c"),
                ]
            ),
        )

    def test_boolean_words_inside_line_comment_are_ignored(self):
        self.assertEqual(
            self.build_ast("$a and // or $b and $d\n$c"),
            AndNode(
                children=[
                    StringNode("$a"),
                    StringNode("$c"),
                ]
            ),
        )

    def test_positional_at_predicate_becomes_string_node(self):
        """A positional `at` predicate still guarantees the string exists."""
        self.assertEqual(
            self.build_ast("$a at entrypoint"),
            StringNode("$a"),
        )

    def test_positional_in_predicate_becomes_string_node(self):
        """A positional `in` predicate still guarantees the string exists."""
        self.assertEqual(
            self.build_ast("$a in (entrypoint..entrypoint + 10)"),
            StringNode("$a"),
        )

    def test_for_any_positional_branch_is_retained_as_unknown(self):
        """Unsupported for-of syntax must stay conservative while siblings parse."""
        condition_ast = _build_condition_ast(
            "(for any of ($fpu*) : ($ at entrypoint)) or $fpu2 in (entrypoint..entrypoint + 10)",
            {"$fpu1", "$fpu2", "$fpu3"},
        )

        self.assertEqual(
            condition_ast,
            OrNode(
                children=[
                    UnknownNode(raw_text=("for ($fpu1 or $fpu2 or $fpu3) : ($ at entrypoint)")),
                    StringNode("$fpu2"),
                ]
            ),
        )

    def test_condition_metadata(self):
        cases = (
            ("any of them", 4, ("any", 1)),
            ("all of them", 4, ("all", 4)),
            ("2 of them", 4, ("n_of", 2)),
            ("$a and $b", 4, ("unknown", None)),
        )

        for condition, string_count, expected in cases:
            with self.subTest(condition=condition):
                self.assertEqual(
                    _parse_condition_metadata(condition, string_count),
                    expected,
                )


class TestRequiredStrings(ConditionAstTestCase):
    """Verify strings guaranteed to be present when a condition is true."""

    def required_strings(self, condition: str) -> set[str]:
        """Build the condition and return its required strings."""
        return _required_strings_from_ast(self.build_ast(condition))

    def test_and_requires_both_strings(self):
        self.assertSetEqual(
            self.required_strings("$a and $b"),
            {"$a", "$b"},
        )

    def test_or_requires_no_individual_string(self):
        self.assertSetEqual(
            self.required_strings("$a or $b"),
            set(),
        )

    def test_required_string_outside_or_is_retained(self):
        self.assertSetEqual(
            self.required_strings("($a or $b) and $c"),
            {"$c"},
        )

    def test_common_string_across_or_branches_is_required(self):
        self.assertSetEqual(
            self.required_strings("($a and $b) or ($a and $c)"),
            {"$a"},
        )

    def test_unknown_and_strings_keeps_known_requirements(self):
        self.assertSetEqual(
            self.required_strings("filesize > 5MB and $a and $b"),
            {"$a", "$b"},
        )

    def test_unknown_or_string_has_no_guaranteed_string(self):
        self.assertSetEqual(
            self.required_strings("filesize > 5MB or $a"),
            set(),
        )

    def test_all_of_them_requires_every_string(self):
        self.assertSetEqual(
            self.required_strings("all of them"),
            {"$a", "$b", "$c", "$d"},
        )

    def test_partial_n_of_has_no_guaranteed_string(self):
        self.assertSetEqual(
            self.required_strings("2 of them"),
            set(),
        )

    def test_n_of_requiring_every_child_requires_all_strings(self):
        self.assertSetEqual(
            self.required_strings("4 of them"),
            {"$a", "$b", "$c", "$d"},
        )

    def test_positional_string_is_still_required(self):
        """Ignoring position in broad phase must not lose string requirement."""
        self.assertSetEqual(
            self.required_strings("$a at entrypoint and $b"),
            {"$a", "$b"},
        )

    def test_none_ast_has_no_required_strings(self):
        self.assertSetEqual(
            _required_strings_from_ast(None),
            set(),
        )


class TestRequiredGroups(ConditionAstTestCase):
    """Verify the current top-level-AND required-group extraction."""

    def setUp(self):
        self.groups = [
            {b"aaaa"},
            {b"bbbb"},
            {b"cccc"},
            {b"dddd"},
            {b"aaaa-alt"},
        ]
        self.string_groups = {
            "$a": [0, 4],
            "$b": [1],
            "$c": [2],
            "$d": [3],
        }

    @staticmethod
    def normalise(groups):
        """Make group comparisons independent of list and set ordering."""
        return [frozenset(group) for group in groups]

    def assert_groups_equal(self, actual, expected):
        """Compare atom groups without relying on ordering."""
        self.assertCountEqual(
            self.normalise(actual),
            self.normalise(expected),
        )

    def groups_for(self, condition: str):
        """Build an AST and extract required groups."""
        return _extract_required_groups(
            self.build_ast(condition),
            self.string_groups,
            self.groups,
        )

    def test_root_or_has_no_required_groups(self):
        self.assertEqual(
            self.groups_for("$a or $b"),
            [],
        )

    def test_plain_top_level_and_strings_have_no_required_groups(self):
        self.assertEqual(
            self.groups_for("$a and $b"),
            [],
        )

    def test_top_level_and_extracts_direct_or_child(self):
        self.assert_groups_equal(
            self.groups_for("filesize > 5MB and ($a or $b)"),
            [
                {b"aaaa"},
                {b"aaaa-alt"},
                {b"bbbb"},
            ],
        )

    def test_multiple_direct_or_children_are_flattened(self):
        self.assert_groups_equal(
            self.groups_for("($a or $b) and ($c or $d)"),
            [
                {b"aaaa"},
                {b"aaaa-alt"},
                {b"bbbb"},
                {b"cccc"},
                {b"dddd"},
            ],
        )

    def test_required_string_is_handled_separately_from_required_groups(self):
        condition_ast = self.build_ast("$a and ($b or $c)")

        self.assertSetEqual(
            _required_strings_from_ast(condition_ast),
            {"$a"},
        )
        self.assert_groups_equal(
            _extract_required_groups(
                condition_ast,
                self.string_groups,
                self.groups,
            ),
            [
                {b"bbbb"},
                {b"cccc"},
            ],
        )

    def test_unknown_and_or_branch_still_extracts_groups(self):
        self.assert_groups_equal(
            self.groups_for("filesize > 5MB and ($a or $b)"),
            [
                {b"aaaa"},
                {b"aaaa-alt"},
                {b"bbbb"},
            ],
        )

    def test_unknown_or_string_at_root_has_no_required_groups(self):
        self.assertEqual(
            self.groups_for("filesize > 5MB or $a"),
            [],
        )

    def test_nested_non_string_or_children_are_not_extracted(self):
        self.assertEqual(
            self.groups_for("$a and (($b or $c) or ($d and filesize > 1MB))"),
            [],
        )

    def test_duplicate_and_invalid_group_ids_are_ignored(self):
        string_groups = {
            "$a": [0, 0, 99, -1],
            "$b": [1],
        }

        actual = _extract_required_groups(
            self.build_ast("filesize > 5MB and ($a or $b)"),
            string_groups,
            self.groups,
        )

        self.assert_groups_equal(
            actual,
            [
                {b"aaaa"},
                {b"bbbb"},
            ],
        )


class TestConditionAstEvaluation(unittest.TestCase):
    """Verify evaluation behaviour implemented by _evaluate_condition_ast."""

    def setUp(self):
        self.matches = {
            "$a": {"one", "two"},
            "$b": {"two", "three"},
            "$c": {"two"},
        }

    def test_string_node_returns_its_matches(self):
        self.assertSetEqual(
            _evaluate_condition_ast(
                StringNode("$a"),
                self.matches,
            ),
            {"one", "two"},
        )

    def test_and_intersects_results(self):
        self.assertSetEqual(
            _evaluate_condition_ast(
                AndNode(
                    children=[
                        StringNode("$a"),
                        StringNode("$b"),
                    ]
                ),
                self.matches,
            ),
            {"two"},
        )

    def test_or_unions_results(self):
        self.assertSetEqual(
            _evaluate_condition_ast(
                OrNode(
                    children=[
                        StringNode("$a"),
                        StringNode("$b"),
                    ]
                ),
                self.matches,
            ),
            {"one", "two", "three"},
        )

    def test_n_of_counts_matching_children(self):
        self.assertSetEqual(
            _evaluate_condition_ast(
                NOfNode(
                    required=2,
                    children=[
                        StringNode("$a"),
                        StringNode("$b"),
                        StringNode("$c"),
                    ],
                ),
                self.matches,
            ),
            {"two"},
        )

    def test_unknown_node_returns_empty_set(self):
        self.assertSetEqual(
            _evaluate_condition_ast(
                UnknownNode("filesize > 5MB"),
                self.matches,
            ),
            set(),
        )

    def test_none_ast_returns_empty_set(self):
        self.assertSetEqual(
            _evaluate_condition_ast(
                None,
                self.matches,
            ),
            set(),
        )


class TestLegacyRequiredStringExtraction(unittest.TestCase):
    """Verify the fallback parser used when AST construction fails."""

    def test_extracts_plain_top_level_and_strings(self):
        self.assertSetEqual(
            _extract_required_strings("$a and $b and filesize > 5MB"),
            {"$a", "$b"},
        )

    def test_does_not_treat_or_strings_as_required(self):
        self.assertSetEqual(
            _extract_required_strings("$a or $b"),
            set(),
        )

    def test_complex_part_is_ignored(self):
        self.assertSetEqual(
            _extract_required_strings("$cfg_blob and $sleep_mask and for any i in (1..#s1): (@s1[i] < @s2[1])"),
            {"$cfg_blob", "$sleep_mask"},
        )


class TestRuleSearchPlanIntegration(unittest.TestCase):
    """Verify parse_yara_rules stores current AST planning fields."""

    @staticmethod
    def make_yara_string(name: str, atom: bytes):
        """Create the minimal YaraString expected by parse_yara_rules."""
        yara_string = yara_parse.YaraString()
        yara_string.name = name
        yara_string.atoms = [atom]
        yara_string.modifiers = []
        yara_string.re = b""
        return yara_string

    def test_parse_yara_rules_nocase_uses_small_atom_pass_only(self):
        """Nocase rules must keep the small-atom result and skip yarac-large."""
        parsed_rule = yara_parse.YaraRule()
        parsed_rule.name = "NoCaseRule"

        yara_string = self.make_yara_string("$a", b"aaaa")
        yara_string.modifiers = ["nocase"]
        parsed_rule.strings = [yara_string]

        rule_text = """
        rule NoCaseRule
        {
            strings:
                $a = "aaaa" nocase
            condition:
                $a
        }
        """

        with mock.patch.object(
            yara_parse,
            "_parse_yara_with_exe",
            return_value=[parsed_rule],
        ) as parse_mock:
            rule_atoms, _rule_content, plans = parse_yara_rules(
                rule_text,
                lambda *_args: None,
            )

        self.assertEqual(parse_mock.call_count, 1)
        self.assertEqual(
            parse_mock.call_args.args[0],
            yara_parse.executables["yarac-small"],
        )
        self.assertEqual(rule_atoms["NoCaseRule"], [b"aaaa"])
        self.assertDictEqual(
            plans["NoCaseRule"].string_groups,
            {"$a": [0]},
        )
        self.assertEqual(
            plans["NoCaseRule"].condition_ast,
            StringNode("$a"),
        )

    def test_parse_yara_rules_renames_anonymous_strings(self):
        """Anonymous `$ = ...` strings must remain distinct in the search plan."""
        parsed_rule = yara_parse.YaraRule()
        parsed_rule.name = "AnonymousRule"
        parsed_rule.strings = [
            self.make_yara_string("$", b"aaaa"),
            self.make_yara_string("$", b"bbbb"),
        ]

        rule_text = """
        rule AnonymousRule
        {
            strings:
                $ = "aaaa"
                $ = "bbbb"
            condition:
                2 of them
        }
        """

        with mock.patch.object(
            yara_parse,
            "_parse_yara_with_exe",
            return_value=[parsed_rule],
        ):
            rule_atoms, _rule_content, plans = parse_yara_rules(
                rule_text,
                lambda *_args: None,
            )

        self.assertCountEqual(
            rule_atoms["AnonymousRule"],
            [b"aaaa", b"bbbb"],
        )

        plan = plans["AnonymousRule"]
        self.assertDictEqual(
            plan.string_groups,
            {
                "$anon_0": [0],
                "$anon_1": [1],
            },
        )
        self.assertEqual(
            plan.condition_ast,
            NOfNode(
                required=2,
                children=[
                    StringNode("$anon_0"),
                    StringNode("$anon_1"),
                ],
            ),
        )
        self.assertSetEqual(
            plan.required_strings,
            {"$anon_0", "$anon_1"},
        )

    def test_parse_yara_rules_stores_raw_condition(self):
        """The exact parsed condition text should be retained on the plan."""
        parsed_rule = yara_parse.YaraRule()
        parsed_rule.name = "RawConditionRule"
        parsed_rule.strings = [
            self.make_yara_string("$a", b"aaaa"),
        ]

        rule_text = """
        rule RawConditionRule
        {
            strings:
                $a = "aaaa"
            condition:
                filesize > 1MB and $a
        }
        """

        with mock.patch.object(
            yara_parse,
            "_parse_yara_with_exe",
            return_value=[parsed_rule],
        ):
            _rule_atoms, _rule_content, plans = parse_yara_rules(
                rule_text,
                lambda *_args: None,
            )

        plan = plans["RawConditionRule"]
        self.assertEqual(
            plan.raw_condition,
            "filesize > 1MB and $a",
        )
        self.assertEqual(
            plan.condition_ast,
            AndNode(
                children=[
                    UnknownNode("filesize > 1MB"),
                    StringNode("$a"),
                ]
            ),
        )
        self.assertSetEqual(
            plan.required_strings,
            {"$a"},
        )

    def test_parse_yara_rules_populates_plan_fields(self):
        parsed_rule = yara_parse.YaraRule()
        parsed_rule.name = "Rule"
        parsed_rule.strings = [
            self.make_yara_string("$a", b"aaaa"),
            self.make_yara_string("$b", b"bbbb"),
            self.make_yara_string("$c", b"cccc"),
        ]

        rule_text = """
        rule Rule
        {
            strings:
                $a = "aaaa"
                $b = "bbbb"
                $c = "cccc"
            condition:
                ($a or $b) and $c
        }
        """

        progress_events = []

        def progress_callback(phase, done, total, completed_item):
            progress_events.append((phase, done, total, completed_item))

        with mock.patch.object(
            yara_parse,
            "_parse_yara_with_exe",
            return_value=[parsed_rule],
        ) as parse_mock:
            rule_atoms, rule_content, plans = parse_yara_rules(
                rule_text,
                progress_callback,
            )

        self.assertEqual(parse_mock.call_count, 2)
        self.assertCountEqual(
            rule_atoms["Rule"],
            [b"aaaa", b"bbbb", b"cccc"],
        )
        self.assertIn("Rule", rule_content)
        self.assertIn("Rule", plans)

        plan = plans["Rule"]

        self.assertEqual(
            plan.condition_ast,
            AndNode(
                children=[
                    OrNode(
                        children=[
                            StringNode("$a"),
                            StringNode("$b"),
                        ]
                    ),
                    StringNode("$c"),
                ]
            ),
        )
        self.assertSetEqual(
            plan.required_strings,
            {"$c"},
        )
        self.assertEqual(
            plan.condition_type,
            "unknown",
        )
        self.assertIsNone(plan.required_count)
        self.assertEqual(plan.string_count, 3)

        self.assertCountEqual(
            [frozenset(group) for group in plan.required_groups],
            [
                frozenset({b"aaaa"}),
                frozenset({b"bbbb"}),
            ],
        )

        self.assertDictEqual(
            plan.string_groups,
            {
                "$a": [0],
                "$b": [1],
                "$c": [2],
            },
        )
        self.assertCountEqual(
            [frozenset(group) for group in plan.groups],
            [
                frozenset({b"aaaa"}),
                frozenset({b"bbbb"}),
                frozenset({b"cccc"}),
            ],
        )

        self.assertIn(
            (
                yara_parse.SearchPhaseEnum.ATOM_PARSE,
                1,
                1,
                ("Rule", [b"aaaa", b"bbbb", b"cccc"]),
            ),
            progress_events,
        )


if __name__ == "__main__":
    unittest.main()
