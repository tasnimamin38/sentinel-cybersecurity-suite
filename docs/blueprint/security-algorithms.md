# SENTINEL — Security Algorithms and Decision Models

**Algorithm set:** 0.3
**Objective:** Deterministic, bounded, explainable defensive assessment inside a time-bounded authorization scope.

## 1. Hostname authorization

1. Trim whitespace and one trailing dot.
2. Reject URL schemes, paths, fragments, queries, user information and IP literals.
3. Convert Unicode labels to IDNA ASCII and lowercase.
4. Validate DNS label syntax and total hostname length.
5. Normalize configured allowlist entries identically.
6. Authorize only exact hostname match or a proper subdomain boundary.

A raw suffix match is invalid. <code>example.com.attacker.invalid</code> must never match the allowlisted <code>example.com</code>.

## 2. Registered-asset authorization

Each registered asset records owner, environment, criticality, tags, authorization reference and timezone-aware expiry.

The assessment gate is:

~~~text
asset = load_asset(asset_id)
if asset does not exist: NOT_FOUND
if asset.status != "active": DENY
if authorization_expires_at <= utc_now(): DENY
if hostname not inside configured server allowlist: DENY
context = { asset_criticality, asset_id, environment }
run bounded posture assessment
~~~

The authorization reference is an operator-supplied approval/change identifier; SENTINEL does not independently verify that the referenced approval exists in an external ticketing system.

## 3. DNS validation and pinned HTTPS transport

~~~text
canonical_host = authorize_and_normalize(input, allowlist)
answers = resolve_A_and_AAAA(canonical_host)
if answers is empty: DENY
if any answer is malformed or not globally routable: DENY
if answer_count > configured_limit: DENY

deadline = monotonic_now + timeout
for ip in unique(answers):
    connect TCP to literal ip:443
    start TLS with server_hostname=canonical_host
    verify certificate chain and hostname
    send one GET / HTTP/1.1
      Host: canonical_host
      Connection: close
    read only through CRLF-CRLF
    cap response headers at 64 KiB
    do not follow redirects
    do not consume the response body
    close socket
~~~

The literal-IP connection removes the application-level resolve/validate/re-resolve window. It does not replace an egress firewall/proxy that checks destinations at connection time.

## 4. Explainable risk v2

Severity weights:

| Severity | Base points |
|---|---:|
| Critical | 100 |
| High | 70 |
| Medium | 35 |
| Low | 10 |
| Info | 1 |

Confidence is clamped to 0.25–1.0. Asset criticality is clamped to 0.5–1.5. Duplicate <code>(category, code)</code> findings count once; the highest weighted instance is retained.

P = sum(severity_points × confidence × asset_criticality)

RiskScore = round(100 × (1 − exp(−P / 50)))

Any critical finding forces a score of 100 and <code>critical</code> level.

| Score | Level |
|---:|---|
| 0 | Informational |
| 1–39 | Low |
| 40–69 | Moderate |
| 70–89 | High |
| 90–100 | Critical |

The API stores the model ID, formula, total weighted points, multiplier, unique finding count and top drivers. The score is a SENTINEL prioritization model, not a CVSS calculation.

## 5. Secret scan data handling

- Accept only bounded plain-text request payloads.
- Run selected credential-like regex patterns.
- Never return raw matches; return a redaction marker/fingerprint.
- Never store submitted source text or matched credential values.
- Record only source byte count, finding count and that source was not persisted.
- The pattern set is limited; no-match does not prove source is secret-free.

## 6. Audit hash chain

For every event, serialize a stable payload containing event ID, type, subject, result, details, timestamp and previous hash.

<code>event_hash = SHA256(canonical_event_payload)</code>

The next event references the last recorded event hash. PostgreSQL writes are serialized with a transaction-scoped advisory lock. Verification recalculates each digest and validates previous-hash continuity.

This detects many accidental or partial modifications, but a privileged database operator can rewrite the entire chain. Use externally controlled, signed checkpoints for stronger assurance.

## 7. Control mapping semantics

A control is marked <code>attention</code> when a mapped finding exists in retained assessments. Otherwise it is <code>not_observed</code>. A <code>not_observed</code> status is not a pass, audit opinion or proof of control effectiveness.
