from __future__ import annotations

import unittest

from sniff4hound.ahocorasick import AhoCorasick


class TestAhoCorasick(unittest.TestCase):
    def test_classic_multi_pattern_example(self):
        # The textbook Aho-Corasick example: "she" and "his" only fully
        # match by using the fail links built from "he"/"hers", not by
        # restarting the scan from scratch after a partial match.
        matcher = AhoCorasick(["he", "she", "his", "hers"])
        self.assertEqual(matcher.search("ushers"), {"he", "she", "hers"})
        self.assertEqual(matcher.search("this is his"), {"his"})

    def test_no_match_returns_empty_set(self):
        matcher = AhoCorasick(["needle", "haystack"])
        self.assertEqual(matcher.search("nothing relevant here"), set())

    def test_pattern_is_substring_of_another_pattern(self):
        matcher = AhoCorasick(["admin", "administrator"])
        self.assertEqual(matcher.search("logged in as administrator"), {"admin", "administrator"})
        self.assertEqual(matcher.search("admin panel"), {"admin"})

    def test_overlapping_occurrences_of_same_pattern(self):
        matcher = AhoCorasick(["aa"])
        self.assertEqual(matcher.search("aaaa"), {"aa"})

    def test_empty_pattern_list(self):
        matcher = AhoCorasick([])
        self.assertEqual(matcher.pattern_count, 0)
        self.assertEqual(matcher.search("anything"), set())
        self.assertFalse(matcher.contains_any("anything"))

    def test_empty_and_falsy_patterns_are_ignored(self):
        matcher = AhoCorasick(["", None, "real"])
        self.assertEqual(matcher.pattern_count, 1)
        self.assertEqual(matcher.search("a real match"), {"real"})

    def test_empty_text(self):
        matcher = AhoCorasick(["x"])
        self.assertEqual(matcher.search(""), set())
        self.assertFalse(matcher.contains_any(""))

    def test_duplicate_patterns_are_deduplicated(self):
        matcher = AhoCorasick(["dup", "dup", "dup"])
        self.assertEqual(matcher.pattern_count, 1)

    def test_contains_any_matches_search_truthiness(self):
        matcher = AhoCorasick(["union select", "drop table"])
        self.assertTrue(matcher.contains_any("' union select * from users"))
        self.assertFalse(matcher.contains_any("perfectly normal request"))

    def test_single_character_patterns(self):
        matcher = AhoCorasick(["a", "b", "c"])
        self.assertEqual(matcher.search("xbz"), {"b"})

    def test_large_pattern_set_stays_correct(self):
        # Every "needle-<i>" pattern is itself a substring of "needle-2500"
        # for any i that is a prefix of "2500" (needle-2, needle-25, ...),
        # so the exact match set legitimately includes those too - assert
        # against that directly instead of a hand-picked expectation.
        patterns = [f"needle-{i}" for i in range(5000)]
        matcher = AhoCorasick(patterns)
        text = "prefix needle-2500 and needle-4999 suffix"
        expected = {pattern for pattern in patterns if pattern in text}
        self.assertEqual(matcher.search(text), expected)
        self.assertIn("needle-2500", expected)
        self.assertIn("needle-4999", expected)


if __name__ == "__main__":
    unittest.main()
