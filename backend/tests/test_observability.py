from app.observability import RequestMetrics


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
