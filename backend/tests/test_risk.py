import unittest

from app.services.risk import calculate_risk


class RiskScoringTests(unittest.TestCase):
    def test_critical_finding_produces_critical_score(self):
        result = calculate_risk([{"code": "C1", "severity": "critical"}])
        self.assertEqual(result["level"], "critical")
        self.assertEqual(result["score"], 100)

    def test_single_high_finding_produces_high_level(self):
        result = calculate_risk([{"code": "H1", "severity": "high"}])
        self.assertEqual(result["level"], "high")
        self.assertGreaterEqual(result["score"], 70)

    def test_empty_findings_are_informational(self):
        result = calculate_risk([])
        self.assertEqual(result["level"], "informational")
        self.assertEqual(result["score"], 0)

    def test_duplicate_finding_code_is_counted_once(self):
        findings = [
            {"code": "MISSING_CSP", "severity": "medium", "category": "web"},
            {"code": "MISSING_CSP", "severity": "medium", "category": "web"},
        ]
        result = calculate_risk(findings)
        self.assertEqual(result["counts"]["medium"], 1)
        self.assertEqual(result["explanation"]["unique_findings"], 1)

    def test_low_confidence_reduces_weight_and_score(self):
        full = calculate_risk([{"code": "H1", "severity": "high", "confidence": 1.0}])
        reduced = calculate_risk([{"code": "H1", "severity": "high", "confidence": 0.5}])
        self.assertGreater(full["score"], reduced["score"])

    def test_criticality_multiplier_is_bounded_and_explained(self):
        result = calculate_risk(
            [{"code": "L1", "severity": "low"}],
            context={"asset_criticality": 10},
        )
        self.assertEqual(result["explanation"]["asset_criticality_multiplier"], 1.5)


if __name__ == "__main__":
    unittest.main()