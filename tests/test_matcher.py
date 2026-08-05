"""Matcher tests, driven entirely by recorded evidence bundles.

None of these need a browser, which is the whole point of keeping collection
and matching apart.
"""

from __future__ import annotations

import json
import os
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from wapp2cve import fingerprints, report  # noqa: E402
from wapp2cve.collector import _launch_args, _reason, detect_block  # noqa: E402
from wapp2cve.cpe import (  # noqa: E402
    is_queryable_version,
    normalize_version,
    resolve_cpe,
    virtual_match_string,
)
from wapp2cve.matcher import match, query_plan, resolve_version  # noqa: E402
from wapp2cve.nvd import NvdClient, parse_cve  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


class TechnologyLoadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.techs = fingerprints.load()

    def test_dataset_size(self):
        self.assertGreater(len(self.techs), 7000)

    def test_cpe_coverage(self):
        # 463 technologies carried a CPE when this was written; the dataset is
        # live, so allow for drift but not for a collapse.
        with_cpe = [t for t in self.techs.values() if resolve_cpe(t)]
        self.assertGreater(len(with_cpe), 400)

    def test_broken_regexes_are_rare(self):
        """Patterns dropped for JS-only regex syntax should stay a rounding error."""
        broken = total = 0
        for tech in self.techs.values():
            for patterns in list(tech.headers.values()) + list(tech.js.values()):
                for pattern in patterns:
                    total += 1
                    broken += pattern.regex is None
        self.assertLess(broken / max(total, 1), 0.02)


class MatchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.techs = fingerprints.load()
        cls.detections = {d.name: d for d in match(load_fixture("wordpress_nginx"), cls.techs)}

    def test_detects_nginx_version_from_server_header(self):
        self.assertIn("Nginx", self.detections)
        self.assertEqual(self.detections["Nginx"].version, "1.18.0")

    def test_detects_php_version_from_powered_by_header(self):
        self.assertEqual(self.detections["PHP"].version, "8.1.2")

    def test_detects_wordpress_version_from_meta_generator(self):
        self.assertEqual(self.detections["WordPress"].version, "6.4.1")

    def test_detects_jquery_version_from_js_global(self):
        self.assertEqual(self.detections["jQuery"].version, "3.4.1")

    def test_implied_technology_is_marked_and_versionless(self):
        mysql = self.detections.get("MySQL")
        self.assertIsNotNone(mysql)
        self.assertTrue(mysql.implied)
        self.assertEqual(mysql.implied_by, "WordPress")
        self.assertIsNone(mysql.version)

    def test_direct_detection_beats_implication(self):
        # PHP is both seen in a header and implied by WordPress.
        self.assertFalse(self.detections["PHP"].implied)


class VersionDslTest(unittest.TestCase):
    def test_single_group(self):
        m = re.search(r"nginx/([\d.]+)", "nginx/1.18.0")
        self.assertEqual(resolve_version(r"\1", m), "1.18.0")

    def test_multiple_groups(self):
        m = re.search(r"(\d+)\.(\d+)", "6.4")
        self.assertEqual(resolve_version(r"\1.\2", m), "6.4")

    def test_literal(self):
        m = re.search(r"magento", "magento")
        self.assertEqual(resolve_version("2", m), "2")

    def test_prefixed_literal(self):
        m = re.search(r"seo-([\d.]+)", "seo-4.1")
        self.assertEqual(resolve_version(r"pro \1", m), "pro 4.1")

    def test_conditional_true_branch(self):
        m = re.search(r"skin/frontend/(?:default|(enterprise))", "skin/frontend/enterprise")
        self.assertEqual(resolve_version(r"\1?1 (Enterprise):1 (Community)", m), "1 (Enterprise)")

    def test_conditional_false_branch(self):
        m = re.search(r"skin/frontend/(?:default|(enterprise))", "skin/frontend/default")
        self.assertEqual(resolve_version(r"\1?1 (Enterprise):1 (Community)", m), "1 (Community)")

    def test_missing_group_yields_empty(self):
        m = re.search(r"nginx(?:/([\d.]+))?", "nginx")
        self.assertEqual(resolve_version(r"\1", m), "")


class VersionHygieneTest(unittest.TestCase):
    def test_clean_versions_pass(self):
        for version in ("1", "1.18", "1.18.0", "6.4.1.2"):
            self.assertTrue(is_queryable_version(version), version)

    def test_dirty_versions_rejected(self):
        # All of these are real outputs of the dataset's version DSL.
        for version in ("1 (Enterprise)", "2+", "pro 3.1", "GA4", "UA", "5-2", "", None):
            self.assertFalse(is_queryable_version(version), version)

    def test_user_input_normalization(self):
        self.assertEqual(normalize_version("v1.18.0"), "1.18.0")
        self.assertEqual(normalize_version(" 1.18 "), "1.18")
        self.assertEqual(normalize_version("1.18.0-1ubuntu"), "1.18.0")


class CpeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.techs = fingerprints.load()

    def test_nginx_vendor_is_f5(self):
        self.assertEqual(resolve_cpe(self.techs["Nginx"]), "cpe:2.3:a:f5:nginx")

    def test_escaped_product_name_survives_split(self):
        # Joomla's CPE product is `joomla\!`.
        self.assertEqual(resolve_cpe(self.techs["Joomla"]), "cpe:2.3:a:joomla:joomla\\!")

    def test_technology_without_cpe_returns_none(self):
        no_cpe = next(t for t in self.techs.values() if not t.cpe)
        self.assertIsNone(resolve_cpe(no_cpe))

    def test_virtual_match_string_appends_version(self):
        self.assertEqual(
            virtual_match_string("cpe:2.3:a:f5:nginx", "1.18.0"), "cpe:2.3:a:f5:nginx:1.18.0"
        )
        self.assertEqual(virtual_match_string("cpe:2.3:a:f5:nginx"), "cpe:2.3:a:f5:nginx")


class QueryPlanTest(unittest.TestCase):
    def test_plan_covers_js_and_dom(self):
        js_paths, dom_rules = query_plan(fingerprints.load())
        self.assertIn("$.fn.jquery", js_paths)
        self.assertGreater(len(dom_rules), 500)
        self.assertEqual(len(dom_rules), len({r.selector for r in dom_rules}))


class BlockDetectionTest(unittest.TestCase):
    def test_clean_page_is_not_blocked(self):
        self.assertIsNone(detect_block(load_fixture("wordpress_nginx")))

    def test_forbidden_status_is_blocked(self):
        self.assertEqual(detect_block({"status": 403, "html": ""}), "HTTP 403")

    def test_challenge_title_is_blocked(self):
        evidence = {"status": 200, "html": "<html><title>Just a moment...</title></html>"}
        self.assertIn("Just a moment", detect_block(evidence) or "")

    def test_challenge_body_signature_is_blocked(self):
        evidence = {"status": 200, "html": "<html><body><div id='cf-chl-widget'></div></body></html>"}
        self.assertIsNotNone(detect_block(evidence))


class ApiKeyStorageTest(unittest.TestCase):
    """A wrong key must be replaceable without hunting for the config file."""

    def _with_temp_config(self, body):
        import contextlib
        import io
        import tempfile

        from wapp2cve import cli

        original = (cli.CONFIG_DIR, cli.CONFIG_FILE)
        with tempfile.TemporaryDirectory() as tmp:
            cli.CONFIG_DIR = Path(tmp) / ".wapp2cve"
            cli.CONFIG_FILE = cli.CONFIG_DIR / "config"
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                    io.StringIO()
                ):
                    body(cli)
            finally:
                cli.CONFIG_DIR, cli.CONFIG_FILE = original

    def test_saving_replaces_the_previous_key(self):
        def body(cli):
            cli.save_api_key("wrong-key")
            self.assertEqual(cli.read_config()["api_key"], "wrong-key")
            cli.save_api_key("right-key")
            self.assertEqual(cli.read_config()["api_key"], "right-key")

        self._with_temp_config(body)

    def test_empty_value_clears_the_key(self):
        def body(cli):
            cli.save_api_key("wrong-key")
            cli.save_api_key("")
            self.assertEqual(cli.read_config()["api_key"], "")

        self._with_temp_config(body)

    def test_environment_variable_wins_over_the_file(self):
        def body(cli):
            cli.save_api_key("from-file")
            os.environ["NVD_API_KEY"] = "from-env"
            try:
                self.assertEqual(cli.get_api_key(), "from-env")
            finally:
                del os.environ["NVD_API_KEY"]

        self._with_temp_config(body)


class NvdKeyHintTest(unittest.TestCase):
    def test_auth_status_hints_at_the_key_only_when_one_is_set(self):
        self.assertIn("--api-key", NvdClient("some-key")._key_hint(404))
        self.assertEqual(NvdClient(None)._key_hint(404), "")
        self.assertEqual(NvdClient("some-key")._key_hint(500), "")


class LaunchArgsTest(unittest.TestCase):
    def test_no_sandbox_only_when_root(self):
        import wapp2cve.collector as mod

        original = getattr(mod.os, "geteuid", None)
        try:
            mod.os.geteuid = lambda: 0
            self.assertIn("--no-sandbox", _launch_args())
            mod.os.geteuid = lambda: 1000
            self.assertNotIn("--no-sandbox", _launch_args())
        finally:
            if original is None:
                del mod.os.geteuid
            else:
                mod.os.geteuid = original


class NavigationErrorTest(unittest.TestCase):
    """A dead host should produce one sentence, not a Playwright stack trace."""

    def test_known_chromium_errors_are_explained(self):
        exc = Exception(
            "Page.goto: net::ERR_NAME_NOT_RESOLVED at https://nope.example\nCall log:\n  - ..."
        )
        self.assertEqual(_reason(exc), "DNS lookup failed")

    def test_timeout_suggests_the_flag(self):
        exc = Exception("Page.goto: Timeout 30000ms exceeded.\nCall log:\n  - navigating")
        self.assertIn("--timeout", _reason(exc))

    def test_unknown_error_keeps_first_line_only(self):
        exc = Exception("Page.goto: something new\nCall log:\n  - noise")
        self.assertEqual(_reason(exc), "something new")


class ReportTest(unittest.TestCase):
    def test_render_groups_and_footers(self):
        results = [
            report.TechResult(
                name="Nginx",
                status=report.QUERIED,
                version="1.18.0",
                cves=[
                    {"id": "CVE-2021-23017", "score": 9.4, "summary": "Resolver off-by-one write"}
                ],
            ),
            report.TechResult(name="Cloudflare", status=report.NO_VERSION),
            report.TechResult(name="MySQL", status=report.IMPLIED),
            report.TechResult(name="Google Analytics", status=report.NO_CPE),
            report.TechResult(name="Magento", status=report.DIRTY_VERSION, version="1 (Community)"),
        ]
        text = report.render("https://example.test/", results)
        self.assertIn("[Nginx 1.18.0]", text)
        self.assertIn("CVE-2021-23017", text)
        self.assertIn("[NO VERSION]  Cloudflare", text)
        self.assertIn("[IMPLIED]", text)
        self.assertIn("[NO CPE]", text)
        self.assertIn("[BAD VERSION] Magento (1 (Community))", text)

    def test_long_lists_are_truncated_without_all(self):
        cves = [{"id": f"CVE-2020-{i:04d}", "score": 5.0, "summary": "x"} for i in range(25)]
        results = [
            report.TechResult(name="Nginx", status=report.QUERIED, version="1.0", cves=cves)
        ]
        self.assertIn("+15 more, use --all to see them", report.render("u", results))
        self.assertNotIn("more, use --all", report.render("u", results, show_all=True))


class CvssMetricTest(unittest.TestCase):
    """NVD scores on 3.1; a 4.0 entry is a second opinion, not a replacement."""

    @staticmethod
    def _cve(**metrics):
        payload = {"id": "CVE-2025-1217", "descriptions": [{"lang": "en", "value": "x"}]}
        payload["metrics"] = {
            key: [{"type": "Primary" if key == "cvssMetricV31" else "Secondary",
                   "cvssData": {"baseScore": score, "baseSeverity": "MEDIUM",
                                "vectorString": f"{key}-vector"}}]
            for key, score in metrics.items()
        }
        return payload

    def test_v31_stays_the_headline_when_both_exist(self):
        parsed = parse_cve(self._cve(cvssMetricV31=3.1, cvssMetricV40=6.3))
        self.assertEqual(parsed["score"], 3.1)
        self.assertEqual(parsed["metric"], "v3.1")
        self.assertEqual(parsed["score_v40"], 6.3)

    def test_v40_is_used_when_it_is_the_only_score(self):
        parsed = parse_cve(self._cve(cvssMetricV40=6.3))
        self.assertEqual(parsed["score"], 6.3)
        self.assertEqual(parsed["metric"], "v4.0")

    def test_no_metrics_at_all(self):
        parsed = parse_cve({"id": "CVE-2025-0001"})
        self.assertIsNone(parsed["score"])
        self.assertIsNone(parsed["score_v40"])
        self.assertEqual(parsed["metric"], "")


class Cvss40ColumnTest(unittest.TestCase):
    def _render(self, cve):
        return report.render(
            "u", [report.TechResult(name="PHP", status=report.QUERIED, version="8.1.2", cves=[cve])]
        )

    def test_both_scores_are_shown_side_by_side(self):
        text = self._render(
            {"id": "CVE-2025-1217", "score": 3.1, "metric": "v3.1", "score_v40": 6.3, "summary": "x"}
        )
        self.assertIn("3.1", text)
        self.assertIn("v4:6.3", text)
        self.assertIn("[CVSS]", text)

    def test_nothing_extra_without_a_v40_score(self):
        text = self._render({"id": "CVE-2021-23017", "score": 9.4, "metric": "v3.1", "summary": "x"})
        self.assertNotIn("v4:", text)
        self.assertNotIn("[CVSS]", text)

    def test_a_v40_only_cve_is_not_printed_twice(self):
        text = self._render(
            {"id": "CVE-2025-1217", "score": 6.3, "metric": "v4.0", "score_v40": 6.3, "summary": "x"}
        )
        self.assertNotIn("v4:", text)


class JsonOutputTest(unittest.TestCase):
    """--json feeds pipelines, so stdout has to parse on its own."""

    def test_render_json_round_trips(self):
        results = [
            report.TechResult(
                name="PHP",
                status=report.QUERIED,
                version="8.1.2",
                cves=[{"id": "CVE-2025-1217", "score": 3.1, "score_v40": 6.3, "summary": "café"}],
            ),
            report.TechResult(name="Cloudflare", status=report.NO_VERSION),
        ]
        raw = report.render_json("https://example.test/", results)
        self.assertIn("café", raw)  # ensure_ascii=False: summaries stay readable
        parsed = json.loads(raw)
        self.assertEqual(parsed["url"], "https://example.test/")
        self.assertEqual(parsed["results"][0]["cves"][0]["score_v40"], 6.3)
        self.assertEqual(parsed["results"][1]["status"], report.NO_VERSION)

    def test_empty_results_are_still_json(self):
        self.assertEqual(json.loads(report.render_json("u", []))["results"], [])

    def test_status_messages_keep_off_stdout(self):
        import contextlib
        import io
        import tempfile

        from wapp2cve.cli import build_parser, run

        evidence = {"url": "https://empty.test/", "final_url": "https://empty.test/", "status": 200,
                    "headers": {}, "cookies": {}, "meta": {}, "html": "<html></html>", "text": "",
                    "scriptSrc": [], "scripts": [], "xhr": [], "js": {}, "dom": {}, "blocked": None}
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "evidence.json"
            bundle.write_text(json.dumps(evidence), encoding="utf-8")
            copy = Path(tmp) / "copy.json"
            args = build_parser().parse_args(
                ["--from-evidence", str(bundle), "--json", "--save-evidence", str(copy)]
            )
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(run(args), 0)
        json.loads(out.getvalue())  # raises if a status line leaked into stdout
        self.assertIn("[*]", err.getvalue())


if __name__ == "__main__":
    unittest.main()
