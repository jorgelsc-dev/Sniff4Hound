"""Public Suffix List backed domain hierarchy."""

from __future__ import annotations

import unittest

from sniff4hound import domain_names


class DomainNamesTests(unittest.TestCase):
    def test_the_complete_public_suffix_list_is_bundled(self):
        counts = domain_names.rule_counts()
        self.assertGreater(counts["exact"], 9_000)
        self.assertGreater(counts["wildcard"], 100)
        self.assertGreater(counts["exception"], 5)

    def test_regular_and_multilevel_public_suffixes(self):
        self.assertEqual(domain_names.registrable_domain("api.eu.example.com"), "example.com")
        self.assertEqual(domain_names.registrable_domain("api.example.co.uk"), "example.co.uk")

    def test_private_wildcard_and_exception_rules_are_applied(self):
        self.assertEqual(domain_names.registrable_domain("a.user.blogspot.com"), "user.blogspot.com")
        self.assertEqual(domain_names.registrable_domain("a.b.ck"), "a.b.ck")
        self.assertEqual(domain_names.registrable_domain("a.www.ck"), "www.ck")

    def test_local_names_and_ip_literals_remain_useful(self):
        self.assertEqual(domain_names.registrable_domain("printer.local"), "printer.local")
        self.assertEqual(domain_names.registrable_domain("wpad"), "wpad")
        self.assertEqual(domain_names.registrable_domain("192.0.2.1"), "192.0.2.1")

    def test_describe_separates_the_subdomain(self):
        self.assertEqual(
            domain_names.describe("mobile.events.example.co.uk"),
            {"base_domain": "example.co.uk", "subdomain": "mobile.events", "is_subdomain": True},
        )


if __name__ == "__main__":
    unittest.main()
