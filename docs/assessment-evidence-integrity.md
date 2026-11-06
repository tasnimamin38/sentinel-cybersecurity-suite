# Assessment evidence integrity

SENTINEL 0.20 anchors each newly completed assessment snapshot to the existing
sequence-numbered, hash-linked audit journal. The application stores no new
signing key and does not create a second integrity database.

## What is anchored

When an assessment is persisted, SENTINEL canonicalizes this versioned payload:

- format identifier: `sentinel.assessment.evidence.v1`
- assessment and asset identifiers
- target, status, score and risk level
- complete findings and evidence JSON values
- assessment creation timestamp normalized to UTC ISO-8601

The JSON is serialized with sorted object keys, compact separators, UTF-8,
`ensure_ascii=false` and non-finite numbers rejected. Array order is preserved.
SENTINEL computes SHA-256 over those bytes and records the hex digest in the
same `assessment.completed` event that is appended to the audit chain. The
assessment row and event are committed by the caller's existing transaction.

The digest is an integrity anchor; it is not a digital signature. It does not
establish who produced the assessment or provide non-repudiation.

## Verify one assessment

Use an authenticated credential with `assessment.read`:

```http
GET /api/v1/assessments/{assessment_id}/evidence-integrity
X-API-Key: <service-key>
```

The endpoint returns identifiers, digest values, audit sequence/event metadata,
separate payload and audit-chain results, and bounded error messages. It does not
return findings or evidence contents. Unknown assessment IDs return HTTP 404.

Important response fields:

| Field | Meaning |
|---|---|
| `integrity_valid` | True only when the current snapshot matches its digest and the audit chain through the anchor verifies |
| `verification_status` | `verified`, `invalid` or `incomplete_legacy` |
| `payload_digest_matches` | Whether the current snapshot matches the digest recorded in the completion event |
| `audit_chain_valid` | Whether the relevant sequence/hash prefix verifies independently |
| `audit_chain_status` | The audit journal verifier's own status |
| `evidence_sha256` / `computed_sha256` | Recorded and recomputed digest, when available |

## Status semantics

- `verified`: the completion event contains a well-formed digest, the current
  assessment matches it, and the audit chain through that event is valid.
- `invalid`: a digest is malformed, the snapshot has changed, the completion
  anchor is duplicated, or the relevant audit chain is invalid.
- `incomplete_legacy`: the assessment has no matching completion event or its
  event predates digest anchoring. Legacy records are never retroactively
  labelled verified.

A payload mismatch is always `invalid`, even where earlier unsealed audit
records make the wider chain incomplete. The payload result and journal result
remain separate so operators can identify the reason.

## Assurance limits and operations

SHA-256 detects changes to the stored snapshot when compared with its audit
anchor. A privileged database operator who can rewrite the assessment, the
completion event and the entire hash chain can still recompute the data. This
feature does not replace the existing offline Ed25519 signed audit checkpoint
workflow. Export and sign checkpoints on a schedule, and preserve them in an
independently controlled or immutable destination.

The digest is deterministic for the canonical JSON snapshot, but this endpoint
does not assess whether the original scanner observations were truthful,
whether the assessment was authorized, or whether evidence was collected
completely. Those controls remain separate parts of SENTINEL's security model.
