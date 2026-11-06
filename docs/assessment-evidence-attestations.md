# Signed Assessment Evidence Attestations

SENTINEL 0.21 adds an offline Ed25519 signature over the verified assessment-evidence anchor introduced in 0.20. It provides a portable signature for one assessment ID, evidence digest and completion-event anchor.

## Security boundary

The signer accepts an assessment-integrity response only when all five checks pass:

- `integrity_valid is True`
- `payload_digest_matches is True`
- `audit_chain_valid is True`
- `verification_status == "verified"`
- `audit_chain_status == "verified"`

Legacy assessments, missing anchors, malformed digests, duplicate/ambiguous events, invalid chains and digest mismatches must not be signed. The signature authenticates the exported digest and audit anchor; it does not prove that scanner observations were truthful or that a target was safe. It also does not prevent a privileged database operator from rewriting the database. Keep signed artifacts and public keys in independently controlled, write-protected storage.

## Signed payload

A deterministic UTF-8 JSON payload (sorted keys, compact separators, non-finite values rejected) contains:

| Field | Meaning |
|---|---|
| `format` | `sentinel.assessment.evidence-attestation.v1` |
| `assessment_id` | Assessment identifier |
| `evidence_sha256` | Versioned evidence snapshot digest |
| `audit_event_id` | Completion event identifier |
| `audit_sequence_no` | Positive audit sequence |
| `audit_event_hash` | Hash-linked event hash |
| `signed_at` | Timezone-aware ISO-8601 timestamp |

The envelope declares Ed25519, includes a SHA-256 key ID derived from the raw public key, the exact payload and a Base64 64-byte signature. Unknown or missing schema fields are rejected.

## Operator workflow

Run commands from `backend`. Never place a private key in source control, containers, CI variables, the application database, a shared drive or an application-readable directory.

### 1. Generate an offline key pair

Use the existing audit-checkpoint utility. Store the encrypted private key offline and protect it with a strong passphrase. The utility refuses to overwrite existing key files.

```bash
cd backend
python -m scripts.audit_checkpoint generate-key \
  --private-key /secure/offline/sentinel-attestation-private.pem \
  --public-key /secure/offline/sentinel-attestation-public.pem
```

On POSIX systems, keep private-key permissions owner-only (for example `chmod 600`). Protect a recovery copy under your key-custody policy.

### 2. Export the current integrity response

Through an authenticated operator session, save the response from `GET /api/v1/assessments/{assessment_id}/evidence-integrity` to a JSON file. Preserve the response as received. Never edit verification flags or anchor values by hand.

### 3. Sign offline

```bash
python -m scripts.assessment_attestation sign \
  --input /secure/evidence/assessment-integrity.json \
  --private-key /secure/offline/sentinel-attestation-private.pem \
  --output /secure/evidence/assessment-attestation.signed.json
```

The command prompts for the private-key passphrase. The output is created without overwriting an existing path and with owner-only permissions on POSIX systems. Non-verified, legacy or malformed responses are rejected.

### 4. Verify signature and current anchor

```bash
python -m scripts.assessment_attestation verify \
  --input /secure/evidence/assessment-attestation.signed.json \
  --public-key /secure/offline/sentinel-attestation-public.pem \
  --current /secure/evidence/assessment-integrity.json
```

Omit `--current` only for an offline cryptographic-signature check. With `--current`, the live fully verified response must match the signed assessment ID, evidence digest, audit event ID, sequence and event hash exactly.

## Custody and failure handling

- Keep private keys offline, encrypted and access-controlled; distribute public keys through a separately authenticated channel.
- Record key IDs. Retain retired public keys so historical attestations remain verifiable after rotation.
- Preserve signed artifacts separately from the production database.
- A non-zero CLI exit indicates malformed input, a non-verified source, wrong key, altered payload, invalid signature, mismatched current anchor or file error. Treat verification failure as an integrity incident; do not auto-sign altered data.

## Tests

`backend/tests/test_assessment_attestation.py` covers valid round-trip, refusal of unverified/legacy states, malformed anchors, payload tampering, wrong public key, current-anchor mismatch, naive timestamps and unsupported envelope fields.
