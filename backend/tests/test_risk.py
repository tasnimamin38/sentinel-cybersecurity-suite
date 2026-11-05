import unittest

from app.services.risk import calculate_risk


class RiskScoringTests(unittest.TestCase):
    def test_critical_finding_produces_critical_score(self):
        result = calculate_risk([{"severity": "critical"}])
        self.assertEqual(result["level"], "critical")
        self.assertEqual(result["score"], 100)

    def test_single_high_finding_produces_high_level(self):
        result = calculate_risk([{"severity": "high"}])
        self.assertEqual(result["level"], "high")
        self.assertGreaterEqual(result["score"], 70)

    def test_empty_findings_are_informational(self):
        result = calculate_risk([])
        self.assertEqual(result["level"], "informational")
        self.assertEqual(result["score"], 0)


if __name__ == "__main__":
    unittest.main()