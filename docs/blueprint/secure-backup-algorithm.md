## 8. Encrypted PostgreSQL backup envelope

Backup encryption uses a versioned binary envelope:

- Fixed magic/version marker: `SNTLBK01`
- Fresh cryptographically random 96-bit GCM nonce per archive
- One-byte key-ID length followed by a bounded ASCII key identifier
- AES-256-GCM ciphertext followed by the 128-bit authentication tag
- The complete header is authenticated as additional authenticated data (AAD)

The encryption key is a Base64-encoded 32-byte value supplied only through the operator environment or secret-manager injection. The key ID is non-secret and must match the configured key during restore. Encryption and decryption stream fixed-size chunks; decryption writes only to a mode-600 temporary file and atomically publishes it after tag verification. On authentication failure, the temporary plaintext is removed and no output archive is published.

A SHA-256 sidecar is retained for early accidental-corruption detection; it is not an authenticity mechanism. The authenticated encryption tag provides integrity/authenticity for ciphertext. The encryption key and key-version mapping must be retained separately. Key loss means backup loss. This design does not claim KMS/HSM integration, off-site retention, secure erasure on SSDs, automatic key rotation or disaster-recovery certification.
