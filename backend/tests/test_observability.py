import json
import logging

from app.observability import RequestMetrics, log_http_request


def test_unknown_methods_and_invalid_status_are_normalized():
    metrics = RequestMetrics()
    metrics.observe("BREW", "unmatched", 700, 0.2)

    payload = metrics.render()

    assert 'method="OTHER",route="unmatched",status_code="500"' in payload
    assert 'le="+Inf"' in payload
    assert "sentinel_http_request_duration_seconds_count" in payload


def test_duration_histogram_uses_cumulative_buckets():
    metrics = RequestMetrics()
    metrics.observe("GET", "/healthz", 200, 0.006)

    payload = metrics.render()

    assert 'route="/healthz",le="0.005"} 0' in payload
    assert 'route="/healthz",le="0.01"} 1' in payload
    assert 'route="/healthz",le="+Inf"} 1' in payload



def test_structured_request_event_contains_only_bounded_safe_fields(caplog):
    request_id = "a" * 32
    with caplog.at_level(logging.INFO, logger="sentinel.access"):
        log_http_request(
            request_id=request_id,
            method="BREW",
            route_template="/api/v1/assets/{asset_id}",
            status_code=401,
            duration_seconds=0.125,
        )

    record = next(item for item in caplog.records if item.name == "sentinel.access")
    event = json.loads(record.getMessage())

    assert event == {
        "timestamp": event["timestamp"],
        "event": "http_request",
        "request_id": request_id,
        "method": "OTHER",
        "route": "/api/v1/assets/{asset_id}",
        "status_code": 401,
        "duration_ms": 125.0,
    }
    assert set(event) == {
        "timestamp",
        "event",
        "request_id",
        "method",
        "route",
        "status_code",
        "duration_ms",
    }
    assert "query" not in event
    assert "client_ip" not in event
    assert "api_key" not in event
