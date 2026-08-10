# Nyx Core API Contract (v1)

- [Purpose](#purpose)
- [Design Principles](#design-principles)
- [Scope (v1)](#scope-v1)
- [Core Types](#core-types)
  - [Repository Identifier](#repository-identifier)
  - [Secret Type](#secret-type)
  - [Secret Record](#secret-record)
  - [Session Context](#session-context)
- [Operation Contract](#operation-contract)
  - [Repository Operations](#repository-operations)
  - [Secret Operations](#secret-operations)
- [Output Shapes](#output-shapes)
  - [SecretSummary](#secretsummary)
  - [SecretRecord Masking Rule](#secretrecord-masking-rule)
- [Error Model](#error-model)
- [Adapter Mapping](#adapter-mapping)
- [Invariants and Security Constraints](#invariants-and-security-constraints)
- [Compatibility](#compatibility)

## Purpose

This document defines the internal core API used by both Nyx interfaces:

- CLI adapter
- HTTP adapter

The core API owns business logic, validation, cryptographic repository access, and consistent error semantics.

## Design Principles

- Single source of truth: CLI and HTTP must call the same core operations.
- Security first: never expose plaintext master password or key material in logs/errors.
- Fail closed: malformed data and unsupported versions are hard errors.
- Stable behavior: same input state leads to same result independent of interface.

## Scope (v1)

Repository lifecycle:

- create
- unlock
- lock
- status
- change master password
- delete

Secret lifecycle:

- add
- list
- search by title
- get by id
- get by title
- update
- delete

## Core Types

### Repository Identifier

The core uses a repository identity independent of transport:

```text
RepositoryName: string
```

Rules:

- unique in local Nyx server/runtime scope
- case-sensitive in v1
- validated by adapter and core

Canonical repository name rule (v1):

- Repository identity is based on file name only; parent path is not part of identity.
- For file-based input, take the base file name and then take the substring before the first `.`.
- If no `.` exists in the base file name, use the full base file name.
- Examples:
  - `/myparentfolder/myrepo.json` -> `myrepo`
  - `myrepo.xx.yy` -> `myrepo`
  - `myrepo` -> `myrepo`

Validation and collision rules:

- Derived or provided `repoName` must not be empty.
- `repoName` must not contain path separators.
- Names are unique by canonical `repoName`; two different file paths that derive the same name refer to the same repository identity.

Note:

- CLI may still accept filesystem input options, but adapter resolves them to canonical `repoName` before calling core.
- HTTP accepts canonical `repoName` directly.

### Secret Type

```text
SecretType = "password" | "certificate" | "information"
```

### Secret Record

```json
{
  "id": "sec_01...",
  "type": "password",
  "title": "GitHub",
  "notes": "optional",
  "createdAt": "2026-07-20T10:01:00Z",
  "updatedAt": "2026-07-20T10:02:00Z",
  "name": "alice@example.com",
  "password": "..."
}
```

Field rules by type:

- password: name, password
- certificate: certificate, privateKey
- information: content

Common rules:

- title must be unique in repository
- timestamps are UTC ISO 8601

### Session Context

```text
SessionToken: string
```

- required for all operations except create and unlock
- HTTP session is token-scoped and repository-scoped
- multiple HTTP sessions may exist for the same repository
- CLI uses repository-scoped local session state

## Operation Contract

Pseudo signature format:

```text
Operation(Input, Context) -> Result | CoreError
```

### Repository Operations

#### Create Repository

```text
createRepository({ repoName, masterPassword })
  -> { repoName, createdAt }
```

Behavior:

- creates new encrypted repository file using repository format spec
- fails if repoName already exists

#### Unlock Repository

```text
unlockRepository({ repoName, masterPassword })
  -> { repoName, sessionToken, expiresAt }
```

Behavior:

- validates password against repository metadata
- creates short-lived local session

#### Lock Repository

```text
lockRepository({ repoName }, { sessionToken })
  -> {}
```

Behavior:

- CLI mode: invalidates CLI session for repoName
- HTTP mode: invalidates only the current token session for repoName

#### Get Repository Status

```text
getRepositoryStatus({ repoName }, { sessionToken })
  -> { repoName, locked, secretCount, updatedAt }
```

#### Change Repository Password

```text
changeRepositoryPassword({ repoName, currentPassword, newPassword }, { sessionToken })
  -> {}
```

Behavior:

- re-wraps DEK with new KEK according to repository format spec

#### Delete Repository

```text
deleteRepository({ repoName }, { sessionToken })
  -> {}
```

### Secret Operations

#### Add Secret

```text
addSecret({ repoName, type, title, notes?, typeFields... }, { sessionToken })
  -> SecretSummary
```

#### List Secrets

```text
listSecrets({ repoName }, { sessionToken })
  -> { items: SecretSummary[] }
```

#### Search Secrets By Title

```text
searchSecretsByTitle({ repoName, titleQuery }, { sessionToken })
  -> { items: SecretSummary[] }
```

Matching rule (v1):

- case-insensitive substring match

#### Get Secret By ID

```text
getSecretById({ repoName, secretId, maskSecuredFields = true }, { sessionToken })
  -> SecretRecord
```

#### Get Secret By Title

```text
getSecretByTitle({ repoName, title, maskSecuredFields = true }, { sessionToken })
  -> SecretRecord
```

#### Update Secret

```text
updateSecret({ repoName, secretId, patch }, { sessionToken })
  -> SecretSummary
```

Patch rules:

- partial update allowed
- type cannot be changed in v1
- title uniqueness must remain true
- updating `id` or `createdAt` by user has no effect
- user cannot directly update `updatedAt`; it is program-managed

#### Delete Secret

```text
deleteSecret({ repoName, secretId }, { sessionToken })
  -> {}
```

## Output Shapes

### SecretSummary

```json
{
  "id": "sec_01...",
  "type": "password",
  "title": "GitHub",
  "createdAt": "2026-07-20T10:01:00Z",
  "updatedAt": "2026-07-20T10:02:00Z"
}
```

### SecretRecord Masking Rule

In v1, only `password` field in `password` type is secured.

- if maskSecuredFields=true: password value is masked (for example `********`)
- if maskSecuredFields=false: password value is returned as stored plaintext in decrypted memory context

## Error Model

All core operations return a structured error on failure:

```json
{
  "code": "REPO_NOT_FOUND",
  "message": "Repository not found",
  "details": {}
}
```

Core error codes (v1):

- INVALID_ARGUMENT
- VALIDATION_ERROR
- AUTH_FAILED
- SESSION_EXPIRED
- REPO_LOCKED
- REPO_ALREADY_EXISTS
- REPO_NOT_FOUND
- SECRET_NOT_FOUND
- TITLE_CONFLICT
- FORMAT_UNSUPPORTED
- CRYPTO_ERROR
- IO_ERROR
- INTERNAL_ERROR

Requirements:

- codes are stable for adapters
- messages are safe for users
- details never include plaintext secrets, passwords, or key bytes

## Adapter Mapping

### CLI to Core

Examples:

- nyx repo create -> createRepository
- nyx repo unlock -> unlockRepository
- nyx secret add -> addSecret
- nyx secret get --id -> getSecretById
- nyx secret get --title -> getSecretByTitle

CLI adapter responsibilities:

- prompt for hidden password input when omitted
- map CLI flags into core input object
- map CoreError to CLI exit codes

### HTTP to Core

Examples:

- POST /v1/repos -> createRepository
- POST /v1/repos/{repoName}/unlock -> unlockRepository
- POST /v1/repos/{repoName}/secrets -> addSecret
- GET /v1/repos/{repoName}/secrets/{id} -> getSecretById

HTTP adapter responsibilities:

- parse/validate transport JSON
- pass bearer token as sessionToken context
- map CoreError to HTTP status + error body as defined in [the HTTP API documentation](http.md)

## Invariants and Security Constraints

- core never stores masterPassword after operation completes
- repository writes are atomic
- repository format validation is mandatory before decrypt
- decrypt/search happens in memory only
- no plaintext secret fields in logs

## Compatibility

- this contract is v1 and additive-first
- breaking changes require version bump and migration notes
- adapters must remain backward-compatible within major version
