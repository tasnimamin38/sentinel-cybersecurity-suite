from __future__ import annotations

import json
from threading import Lock

_ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_BUCKETS_SECONDS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, float("inf"))


def _escape_label(value: str) -> str:
    # JSON string escaping is compatible with Prometheus label-value escaping
    # for the quote, backslash and newline characters.
    return json.dumps(value, ensure_ascii=False)[1:-1]


class RequestMetrics:
    """Thread-safe, process-local HTTP metrics with bounded label values."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._requests: dict[tuple[str, str, int], int] = {}
        self._duration_buckets: dict[tuple[str, str], list[int]] = {}
        self._duration_sum: dict[tuple[str, str], float] = {}
        self._duration_count: dict[tuple[str, str], int] = {}

    @staticmethod
    def _labels(method: str, route_template: str, status_code: int) -> tuple[str, str, int]:
        normalized_method = method.upper()
        if normalized_method not in _ALLOWED_METHODS:
            normalized_method = "OTHER"
        # Route templates come from the framework router; never use raw request URLs.
        normalized_route = (
            route_template
            if isinstance(route_template, str) and route_template.startswith("/")
            else "unmatched"
        )
        normalized_status = (
            status_code
            if type(status_code) is int and 100 <= status_code <= 599
            else 500
        )
        return normalized_method, normalized_route, normalized_status

    def observe(
        self,
        method: str,
        route_template: str,
        status_code: int,
        duration_seconds: float,
    ) -> None:
        normalized_method, normalized_route, normalized_status = self._labels(
            method, route_template, status_code
        )
        duration = max(0.0, float(duration_seconds))
        request_key = (normalized_method, normalized_route, normalized_status)
        duration_key = (normalized_method, normalized_route)

        with self._lock:
            self._requests[request_key] = self._requests.get(request_key, 0) + 1
            buckets = self._duration_buckets.setdefault(
                duration_key, [0 for _ in _BUCKETS_SECONDS]
            )
            for index, boundary in enumerate(_BUCKETS_SECONDS):
                if duration <= boundary:
                    buckets[index] += 1
            self._duration_sum[duration_key] = (
                self._duration_sum.get(duration_key, 0.0) + duration
            )
            self._duration_count[duration_key] = self._duration_count.get(duration_key, 0) + 1

    def render(self) -> str:
        lines = [
            "# HELP sentinel_http_requests_total Total HTTP requests handled by this process.",
            "# TYPE sentinel_http_requests_total counter",
        ]
        with self._lock:
            requests = sorted(self._requests.items())
            durations = sorted(self._duration_buckets.items())
            duration_sums = dict(self._duration_sum)
            duration_counts = dict(self._duration_count)
            buckets_snapshot = {key: list(value) for key, value in durations}

        for (method, route, status_code), count in requests:
            labels = (
                f'method="{_escape_label(method)}",'
                f'route="{_escape_label(route)}",status_code="{status_code}"'
            )
            lines.append(f"sentinel_http_requests_total{{{labels}}} {count}")

        lines.extend(
            [
                "# HELP sentinel_http_request_duration_seconds HTTP request duration in seconds.",
                "# TYPE sentinel_http_request_duration_seconds histogram",
            ]
        )
        for (method, route), counts in buckets_snapshot.items():
            for boundary, count in zip(_BUCKETS_SECONDS, counts, strict=True):
                label = "+Inf" if boundary == float("inf") else f"{boundary:g}"
                labels = (
                    f'method="{_escape_label(method)}",'
                    f'route="{_escape_label(route)}",le="{label}"'
                )
                lines.append(f"sentinel_http_request_duration_seconds_bucket{{{labels}}} {count}")
            lines.append(
                "sentinel_http_request_duration_seconds_sum"
                f'{{method="{_escape_label(method)}",route="{_escape_label(route)}"}} '
                f"{duration_sums[(method, route)]:.9f}"
            )
            lines.append(
                "sentinel_http_request_duration_seconds_count"
                f'{{method="{_escape_label(method)}",route="{_escape_label(route)}"}} '
                f"{duration_counts[(method, route)]}"
            )
        return "\n".join(lines) + "\n"


HTTP_METRICS = RequestMetrics()
