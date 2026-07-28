"""Unit tests for ThreatLens IOC classification, scoring, and enrichment."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.ioc import classify, parse_ioc_list
from lib.scoring import (
    looks_like_dga, suspicious_tld, score_ioc, severity_for, apply_reputation,
)
from lib.enricher import enrich_batch


class TestClassification(unittest.TestCase):
    def test_types(self):
        self.assertEqual(classify("8.8.8.8"), "ip")
        self.assertEqual(classify("example.com"), "domain")
        self.assertEqual(classify("https://evil.tld/x"), "url")
        self.assertEqual(classify("44d88612fea8a8f36de82e1278abb02f"), "md5")
        self.assertEqual(classify("a" * 40), "sha1")
        self.assertEqual(classify("a" * 64), "sha256")
        self.assertEqual(classify("user@example.com"), "email")
        self.assertEqual(classify("CVE-2021-44228"), "cve")
        self.assertEqual(classify("not an ioc !!"), "unknown")

    def test_parse_skips_blanks_and_comments(self):
        iocs = parse_ioc_list(["8.8.8.8", "", "# comment", "example.com"])
        self.assertEqual([i.ioc_type for i in iocs], ["ip", "domain"])


class TestScoring(unittest.TestCase):
    def test_dga_detection(self):
        self.assertTrue(looks_like_dga("kq3v9z7x1p0m4w"))
        self.assertFalse(looks_like_dga("google"))
        self.assertFalse(looks_like_dga("microsoft"))

    def test_suspicious_tld(self):
        self.assertEqual(suspicious_tld("free-prize.tk"), "tk")
        self.assertEqual(suspicious_tld("example.com"), "")

    def test_private_ip_is_low(self):
        score, sev, _ = score_ioc("ip", "192.168.1.10")
        self.assertLessEqual(score, 15)
        self.assertIn(sev, ("INFO", "LOW"))

    def test_bad_domain_scores_higher_than_clean(self):
        bad, _, _ = score_ioc("domain", "kq3v9z7x1p0m4w.tk")
        clean, _, _ = score_ioc("domain", "example.com")
        self.assertGreater(bad, clean)

    def test_severity_bands(self):
        self.assertEqual(severity_for(90), "CRITICAL")
        self.assertEqual(severity_for(65), "HIGH")
        self.assertEqual(severity_for(40), "MEDIUM")
        self.assertEqual(severity_for(20), "LOW")
        self.assertEqual(severity_for(5), "INFO")

    def test_reputation_raises_score(self):
        score, sev = apply_reputation(30, malicious=5, suspicious=0)
        self.assertGreaterEqual(score, 70)
        self.assertIn(sev, ("HIGH", "CRITICAL"))


class TestEnrichment(unittest.TestCase):
    def test_batch_enrich_offline(self):
        results = enrich_batch(["8.8.8.8", "kq3v9z7x1p0m4w.tk", "CVE-2021-44228"])
        self.assertEqual(len(results), 3)
        for r in results:
            self.assertTrue(0 <= r.score <= 100)
            self.assertIn(r.severity, ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
        # DGA + suspicious TLD domain should outrank a clean public DNS IP
        by_val = {r.ioc.value: r for r in results}
        self.assertGreater(by_val["kq3v9z7x1p0m4w.tk"].score, by_val["8.8.8.8"].score)

    def test_techniques_attached(self):
        (r,) = enrich_batch(["8.8.8.8"])
        self.assertTrue(any(t.technique_id == "T1071" for t in r.techniques))


if __name__ == "__main__":
    unittest.main()
