"""TLS probe planning regressions; no network access required."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.probe_plan import build_probe_targets, plan_probe, remove_rejected


class ProbePlanTests(unittest.TestCase):
    def test_wikibooks_uses_official_regex_sni_without_deleting_wildcard(self):
        itc = {r"^.*(wikipedia|wikibooks).org$": {".*": {"sni": "mediawiki.org"}}}
        pre = {"*wikibooks.org": {"185.15.59.224": True}}
        targets, removable, skipped = build_probe_targets(list(pre), itc, pre, {})
        self.assertEqual(targets, [("*wikibooks.org", "185.15.59.224", "mediawiki.org")])
        self.assertFalse(removable)
        self.assertFalse(skipped)
        self.assertEqual(remove_rejected({("*wikibooks.org", "185.15.59.224"): "alert"}, pre, removable), [])
        self.assertIn("185.15.59.224", pre["*wikibooks.org"])

    def test_absent_sni_and_explicit_empty_are_distinct(self):
        default = plan_probe("example.com", {"example.com": {".*": {}}}, {})
        disabled = plan_probe("example.com", {"example.com": {".*": {"sni": ""}}}, {})
        self.assertEqual(default.sni, "example.com")
        self.assertEqual(disabled.sni, "")
        self.assertTrue(default.can_remove and disabled.can_remove)

    def test_exact_alert_only_removes_exact_target(self):
        itc = {"one.example.com": {".*": {"sni": "gateway.example.com"}}}
        pre = {"one.example.com": {"192.0.2.1": True, "192.0.2.2": True}}
        targets, removable, _ = build_probe_targets(list(pre), itc, pre, {})
        self.assertEqual(targets[0], ("one.example.com", "192.0.2.1", "gateway.example.com"))
        removed = remove_rejected({("one.example.com", "192.0.2.1"): "alert", ("one.example.com", "192.0.2.2"): "unknown"}, pre, removable)
        self.assertEqual(removed, [("one.example.com", "192.0.2.1")])
        self.assertEqual(pre["one.example.com"], {"192.0.2.2": True})

    def test_conflicting_paths_or_host_rules_are_not_guessed(self):
        itc = {"*.example.com": {".*": {"sni": "one.example"}}, "api.example.com": {".*": {"sni": "two.example"}}}
        plan = plan_probe("api.example.com", itc, {})
        self.assertIsNone(plan.sni)
        self.assertFalse(plan.can_remove)
        itc = {"api.example.com": {"/a": {"sni": "one.example"}, "/b": {"sni": "two.example"}}}
        self.assertIsNone(plan_probe("api.example.com", itc, {}).sni)

    def test_proxy_and_missing_sni_on_another_path_are_ambiguous(self):
        for paths in ({".*": {"proxy": "mirror.example"}}, {"/a": {"sni": "one.example"}, "/b": {"cacheDays": 1}}):
            self.assertIsNone(plan_probe("api.example.com", {"api.example.com": paths}, {}).sni)

    def test_ech_does_not_use_ordinary_sni_probe(self):
        dns = {"ech": {"enabled": True, "use": True, "domains": ["*example.com"]}}
        plan = plan_probe("api.example.com", {"api.example.com": {".*": {"sni": "baidu.com"}}}, dns)
        self.assertIsNone(plan.sni)
        self.assertFalse(plan.can_remove)

    def test_named_javascript_group_and_unparseable_pattern(self):
        itc = {r"^(?<pre>.*)example.com$": {".*": {"sni": "gateway.example"}}}
        self.assertEqual(plan_probe("api.example.com", itc, {}).sni, "gateway.example")
        self.assertIsNone(plan_probe("api.example.com", {"^[": {".*": {"sni": "x"}}}, {}).sni)

    def test_complex_wildcard_and_regex_are_skipped(self):
        self.assertIsNone(plan_probe("img*.example.com", {}, {}).hostname)
        self.assertIsNone(plan_probe("^.*example.com$", {}, {}).hostname)


if __name__ == "__main__":
    unittest.main()