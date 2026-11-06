# Offline signed audit checkpoints

SENTINEL's hash-linked audit journal detects changes to stored events, but a database administrator who can rewrite the entire journal may also recompute the chain. An independently held Ed25519 signing key adds an external trust anchor.

## Security model

- The application exposes a verifiable journal prefix; it never receives or stores the private signing key.
- The operator generates and retains the encrypted Ed25519 private key outside the SENTINEL host.
- A verified checkpoint is signed offline and the signed JSON is copied to independently controlled, append-only or immutable storage.
- Verification checks both the detached signature and, when supplied, the current journal prefix at the exact signed sequence.
- This workflow is an operator-controlled integrity control. It is not automatic archival, a cloud KMS integration, or a claim of certified immutability.

## 1. Generate an offline key pair

Run on a trusted operator workstation, not on the SENTINEL server:

```bash
python backend/scripts/audit_checkpoint.py generate-key \
  --private-key audit-checkpoint-private.pem \
  --public-key audit-checkpoint-public.pem
```

Choose a strong passphrase of at least 12 characters. The private key is written as encrypted PKCS#8 PEM with restrictive file permissions where supported. The loader rejects symlinks, non-regular or empty files, files larger than 64 KiB, and POSIX permissions accessible to group or other users; it reads from one checked file descriptor and verifies the file identity before parsing. Never commit, upload, email, or place the private key on the application host. Keep a protected backup. Distribute the public key to verifiers.

## 2. Export a verified checkpoint

Call the authenticated endpoint:

```bash
curl --fail --silent --show-error \
  -H "X-API-Key: $SENTINEL_API_KEY" \
  "$SENTINEL_BASE_URL/api/v1/audit/integrity" \
  -o audit-integrity.json
```

Only a response with `integrity_valid: true`, `verification_status: "verified"`, and a non-null `checkpoint` can be signed. The signer refuses empty, legacy-incomplete, or invalid journals.

## 3. Sign offline and preserve externally

Transfer `audit-integrity.json` to the trusted signing workstation using an approved secure channel, then run:

```bash
python backend/scripts/audit_checkpoint.py sign \
  --input audit-integrity.json \
  --private-key audit-checkpoint-private.pem \
  --output audit-checkpoint.signed.json
```

The private-key passphrase is requested interactively and is not accepted as a command-line argument. Store `audit-checkpoint.signed.json` with a timestamped retention policy in a separate account, security boundary, or immutable storage system. Retain the relevant public key and its key ID.

## 4. Verify the detached signature and journal prefix

Read the signed sequence number from the signed envelope, then request that exact historical prefix from the current SENTINEL instance:

```bash
curl --fail --silent --show-error \
  -H "X-API-Key: $SENTINEL_API_KEY" \
  "$SENTINEL_BASE_URL/api/v1/audit/integrity?through_sequence=<SIGNED_SEQUENCE>" \
  -o current-prefix.json
```

Run verification on a trusted host:

```bash
python backend/scripts/audit_checkpoint.py verify \
  --input audit-checkpoint.signed.json \
  --public-key audit-checkpoint-public.pem \
  --current current-prefix.json
```

A successful result proves that the supplied public key validates the detached signature and that the currently verified historical prefix matches the signed sequence and event hash. A mismatch, truncated chain, changed event, wrong key, invalid signature, or incomplete chain fails verification.

For signature-only verification without querying SENTINEL, omit `--current`. That verifies the signed artifact, not the current database state.

## Operational requirements and limitations

- Sign and export checkpoints on a defined schedule and after high-impact administrative events.
- Keep private-key custody and signed-checkpoint storage independent from the application and database administrators.
- Back up the private key securely; plan key rotation and preserve old public keys for historical verification.
- The application does not automatically upload checkpoints to object storage. Configure an independently operated retention destination and alerting process.
- A checkpoint is meaningful only when its signature, key custody, sequence and external retention record are verified. This workflow does not replace external penetration testing, backup/restore drills, or independent review.