# Nyx Repository File Format Specification

## 1. Purpose and Scope

This document defines the v1 on-disk format for a Nyx repository file.

Goals:

- Store all repository data in one encrypted local file.
- Never store the master password itself.
- Support secure unlock, lock, and master password rotation.
- Keep format versioned for forward-compatible migration.

Out of scope:

- Daemon-based key/session management.
- OS-specific secure storage integration.
- Backup/export plaintext format (covered by separate spec).

## 2. Security Requirements

The repository format MUST satisfy the following:

- Confidentiality: secret data is encrypted at rest.
- Integrity: tampering is detected during unlock/read.
- Password safety: only password-derived metadata is stored.
- Randomness: salts and nonces are cryptographically random.
- Versioning: format version is explicit and validated.

Nyx v1 threat boundary: protects against offline file theft and tampering, but not a fully compromised host OS.

## 3. Cryptographic Profile (v1)

Required algorithms:

- KDF: Argon2id
- AEAD (Authenticated Encryption with Associated Data) for key wrapping and payload encryption: XChaCha20-Poly1305
- RNG: cryptographically secure OS RNG

Default KDF parameters (v1 baseline):

- memoryKiB: 65536 (64 MiB)
- iterations: 3
- parallelism: 1
- outputLength: 32 bytes

Implementations MAY tune parameters over time, but MUST persist exact parameters in file metadata.

## 4. High-Level Design

Nyx uses envelope encryption:

1. Generate random Data Encryption Key (DEK, 32 bytes) per repository.
2. Derive Key Encryption Key (KEK) from master password using Argon2id and per-repository salt.
3. Wrap (encrypt) DEK with KEK using AEAD.
4. Encrypt repository payload (all secrets and repository data) with DEK using AEAD.

Advantages:

- Master password is never stored.
- Password rotation can re-wrap DEK without re-encrypting full payload.

## 5. File Encoding

The repository file is UTF-8 JSON with base64-encoded binary fields.

Top-level schema (v1):

```json
{
  "format": "nyx-repo",
  "version": 1,
  "kdf": {
    "algorithm": "argon2id",
    "memoryKiB": 65536,
    "iterations": 3,
    "parallelism": 1,
    "saltB64": "..."
  },
  "keyWrap": {
    "algorithm": "xchacha20poly1305",
    "nonceB64": "...",
    "ciphertextB64": "..."
  },
  "payload": {
    "algorithm": "xchacha20poly1305",
    "nonceB64": "...",
    "ciphertextB64": "..."
  }
}
```

Notes:

- `keyWrap.ciphertextB64` contains encrypted DEK and AEAD tag.
- `payload.ciphertextB64` contains encrypted repository plaintext and AEAD tag.
- No secret plaintext appears outside encrypted payload.

## 6. Authenticated Data (AAD)

AAD is used to bind cryptographic metadata and prevent undetected metadata tampering.

v1 AAD strings:

- For DEK wrap: canonical JSON of `{format, version, kdf, keyWrap.algorithm}`
- For payload encryption: canonical JSON of `{format, version, kdf, payload.algorithm}`

Canonical JSON means deterministic key ordering and UTF-8 bytes.

## 7. Repository Plaintext Payload (Encrypted)

When decrypted, payload is JSON with the repository content.

Payload schema (v1):

```json
{
  "schemaVersion": 1,
  "createdAt": "2026-07-20T10:00:00Z",
  "updatedAt": "2026-07-20T10:05:00Z",
  "secrets": [
    {
      "id": "sec_...",
      "type": "password",
      "title": "GitHub",
      "notes": "...",
      "createdAt": "2026-07-20T10:01:00Z",
      "updatedAt": "2026-07-20T10:02:00Z",
      "name": "alice@example.com",
      "password": "..."
    }
  ]
}
```

Rules:

- `title` MUST be unique within one repository.
- `type` MUST be one of: `password`, `certificate`, `information`.
- Required type-specific fields by type:
  - `password`: `name`, `password`
  - `certificate`: `certificate`, `privateKey`
  - `information`: `content`
- Timestamps MUST be UTC ISO 8601.

## 8. Create / Unlock / Rotate Semantics

Create repository:

1. Generate random salt, DEK, and nonces.
2. Derive KEK from password + salt.
3. Wrap DEK into `keyWrap`.
4. Encrypt initial payload with DEK.
5. Write file atomically.

Unlock repository:

1. Parse and validate format/version.
2. Derive KEK from password and stored KDF params.
3. Decrypt `keyWrap` to recover DEK.
4. Decrypt `payload` with DEK.
5. If any AEAD step fails, return authentication error.

Change master password:

1. Unlock using current password.
2. Derive new KEK using new salt and chosen KDF params.
3. Re-wrap same DEK with new KEK.
4. Keep payload ciphertext unchanged.
5. Write updated file atomically.

## 9. Validation Rules

Implementations MUST reject file if:

- `format` is not `nyx-repo`.
- `version` is unsupported.
- KDF or AEAD algorithm name is unsupported.
- Required fields are missing or malformed.
- Any base64 decoding fails.
- Any decrypt/authentication check fails.

Errors MUST NOT leak password, key bytes, or plaintext content.

## 10. Atomic Persistence and File Permissions

Write strategy:

1. Write to temporary file in same directory.
2. fsync temporary file.
3. Atomic rename over target repository file.

File permission guidance:

- Repository file SHOULD be owner-readable/writable only (for example 0600 on POSIX).
- Parent directory SHOULD be least privilege.

## 11. Compatibility and Migration

- `version` is the file container version.
- `payload.schemaVersion` is repository content schema version.
- Future versions MUST provide deterministic migration path.
- Readers MUST fail closed on unknown critical fields/algorithms.

## 12. Non-Goals and Explicit Tradeoffs

- No plaintext indexing is stored in v1; search occurs after decrypting payload in memory.
- v1 favors confidentiality over searchable-at-rest performance.
- Session persistence behavior is not encoded in repository file format.
