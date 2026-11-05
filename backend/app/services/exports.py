import csv
import io
from collections.abc import Iterable, Sequence


def _safe_cell(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        value = str(value)
    if isinstance(value, (int, float)):
        return value
    text = str(value)
    # Spreadsheet formula injection: neutralize cells whose first meaningful
    # character is interpreted as a formula by common spreadsheet software.
    probe = text.lstrip(" \t\r\n")
    if probe.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def render_csv(headers: Sequence[str], rows: Iterable[Sequence[object]]) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow([_safe_cell(value) for value in headers])
    for row in rows:
        writer.writerow([_safe_cell(value) for value in row])
    return buffer.getvalue()
