import unittest

from app.services.exports import render_csv


class CsvExportSafetyTests(unittest.TestCase):
    def test_formula_like_cells_are_neutralized(self):
        rendered = render_csv(
            ["hostname", "owner", "notes"],
            [["example.com", '=HYPERLINK("https://evil.invalid")', "  +SUM(1,2)"]],
        )
        self.assertIn("'=HYPERLINK", rendered)
        self.assertIn("'  +SUM(1,2)", rendered)

    def test_csv_quotes_commas_and_line_breaks(self):
        rendered = render_csv(["notes"], [["one, two\nthree"]])
        self.assertIn('"one, two\nthree"', rendered)


if __name__ == "__main__":
    unittest.main()
