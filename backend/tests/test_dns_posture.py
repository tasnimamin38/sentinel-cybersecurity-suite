import unittest
from unittest.mock import patch

import dns.resolver

from app.services.dns_posture import inspect_dns_posture


class FakeRecord:
    def __init__(self, value):
        self.value = value

    def to_text(self):
        return self.value


class FakeResolver:
    records = {}

    def __init__(self):
        self.timeout = None
        self.lifetime = None

    def resolve(self, name, record_type):
        values = self.records.get((name, record_type))
        if values is None:
            raise dns.resolver.NoAnswer()
        return [FakeRecord(value) for value in values]


class DnsPostureTests(unittest.TestCase):
    def test_well_configured_email_and_certificate_dns_posture(self):
        FakeResolver.records = {
            ("example.com", "MX"): ["10 mail.example.com."],
            ("example.com", "TXT"): ["v=spf1 include:_spf.example -all"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
            ("example.com", "CAA"): ['0 issue "letsencrypt.org"'],
            ("_mta-sts.example.com", "TXT"): ["v=STSv1; id=2026110601"],
            ("_smtp._tls.example.com", "TXT"): ["v=TLSRPTv1; rua=mailto:tls@example.com"],
        }
        with patch("app.services.dns_posture.dns.resolver.Resolver", FakeResolver):
            result, findings = inspect_dns_posture("example.com")
        self.assertTrue(result["mx"])
        self.assertTrue(result["spf"])
        self.assertTrue(result["dmarc"])
        self.assertEqual(result["dmarc_policy"], "reject")
        self.assertTrue(result["caa"])
        self.assertTrue(result["mta_sts"])
        self.assertTrue(result["tls_rpt"])
        self.assertEqual(findings, [])

    def test_caa_policy_is_inherited_from_parent_domain(self):
        FakeResolver.records = {
            ("example.com", "CAA"): ['0 issue "letsencrypt.org"'],
        }
        with patch("app.services.dns_posture.dns.resolver.Resolver", FakeResolver):
            result, findings = inspect_dns_posture("portal.example.com")
        self.assertTrue(result["caa"])
        self.assertEqual(result["caa_source"], "example.com")
        self.assertNotIn("DNS_CAA_MISSING", {item["code"] for item in findings})

    def test_multiple_spf_and_monitor_only_dmarc_are_flagged(self):
        FakeResolver.records = {
            ("example.com", "MX"): ["10 mail.example.com."],
            ("example.com", "TXT"): [
                "v=spf1 include:one.example -all",
                "v=spf1 include:two.example -all",
            ],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none"],
        }
        with patch("app.services.dns_posture.dns.resolver.Resolver", FakeResolver):
            result, findings = inspect_dns_posture("example.com")
        codes = {item["code"] for item in findings}
        self.assertEqual(result["spf_record_count"], 2)
        self.assertIn("DNS_SPF_MULTIPLE", codes)
        self.assertIn("DNS_DMARC_MONITOR_ONLY", codes)
        self.assertIn("DNS_CAA_MISSING", codes)
        self.assertIn("DNS_MTA_STS_MISSING", codes)
        self.assertIn("DNS_TLS_RPT_MISSING", codes)


if __name__ == "__main__":
    unittest.main()
