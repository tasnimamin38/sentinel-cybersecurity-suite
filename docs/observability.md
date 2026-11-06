# SENTINEL Observability — 0.10 baseline

## Enable only for a trusted scraper

Metrics are disabled by default. To enable them, set:

```dotenv
SENTINEL_METRICS_ENABLED=true
SENTINEL_METRICS_TOKEN=<separate-random-secret-at-least-32-characters>
```

Use a random token that is separate from every API key. Production startup rejects metrics-enabled configuration without a strong token. Then recreate the API container. The endpoint is:

```text
GET /metrics
X-Metrics-Token: <SENTINEL_METRICS_TOKEN>
```

The endpoint is not part of the API-key permission matrix and does not consume service-key quota, but it does require the separate `X-Metrics-Token` header. Token comparison is constant-time. The supplied Docker Compose file binds the API only to `127.0.0.1:8000`; preserve that boundary. Do not route `/metrics` through a public ingress, shared reverse proxy, or untrusted network.

## Exported metrics

- `sentinel_http_requests_total{method,route,status_code}`: completed HTTP request count.
- `sentinel_http_request_duration_seconds`: histogram with bounded buckets, sum and count, grouped by normalized method and registered route template.

Methods outside the known HTTP method set are normalized to `OTHER`. Requests without a matched route are grouped as `unmatched`. Route labels use FastAPI's registered route template, never the raw URL path. Histograms omit response status to reduce cardinality.

## Explicit exclusions

The exporter never attaches raw URL paths, query parameters, client IPs, API-key values, credential IDs, hostnames, request bodies or response bodies as labels. Do not add high-cardinality or secret-bearing labels.

## Limitations

Metrics are held in process memory. They reset on restart and are not shared between API replicas or worker processes. A scrape is a point-in-time view of one API process. This baseline is intended for local diagnostics and a trusted single-process scraper. Protect the separate metrics token as a secret and rotate it through deployment configuration if exposed. It is not durable billing, distributed rate limiting, a centralized telemetry backend, tracing, alert delivery or an SLO guarantee.

Before production use, validate network reachability from only the intended scraper, configure retention and dashboards outside SENTINEL, and define alert ownership. Keep metrics disabled when no trusted scraper is configured.
