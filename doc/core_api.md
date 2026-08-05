# Nyx Core API Contract (v1)

## 1. Purpose

This document defines the internal core API used by both Nyx interfaces:

- CLI adapter
- HTTP adapter

The core API owns business logic, validation, cryptographic repository access, and consistent error semantics.

## 2. Design Principles

- Single source of truth: CLI and HTTP must call the same core operations.
- Security first: never expose plaintext master password or key material in logs/errors.
- Fail closed: malformed data and unsupported versions are hard errors.
- Stable behavior: same input state leads to same result independent of interface.

## 3. Scope (v1)

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

## 4. Core Types

### 4.1 Repository Identifier

The core uses a repository identity independent of transport:

```text
RepositoryName: string
```

Rules:

- unique in local Nyx server/runtime scope
- case-sensitive in v1
- validated by adapter and core

Note:

- CLI may still accept filesystem input options, but adapter resolves them to a RepositoryName before calling core.

### 4.2 Secret Type

```text
SecretType = "password" | "certificate" | "information"
```

### 4.3 Secret Record

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

### 4.4 Session Context

```text
SessionToken: string
```

- required for all operations except create and unlock
- session is repository-scoped
- lock invalidates session

## 5. Operation Contract

Pseudo signature format:

```text
Operation(Input, Context) -> Result | CoreError
```

### 5.1 Repository Operations

#### createRepository

```text
createRepository({ repoName, masterPassword })
  -> { repoName, createdAt }
```

Behavior:

- creates new encrypted repository file using repository format spec
- fails if repoName already exists

#### unlockRepository

```text
unlockRepository({ repoName, masterPassword })
  -> { repoName, sessionToken, expiresAt }
```

Behavior:

- validates password against repository metadata
- creates short-lived local session

#### lockRepository

```text
lockRepository({ repoName }, { sessionToken })
  -> {}
```

Behavior:

- invalidates active session for repoName

#### getRepositoryStatus

```text
getRepositoryStatus({ repoName }, { sessionToken })
  -> { repoName, locked, secretCount, updatedAt }
```

#### changeRepositoryPassword

```text
changeRepositoryPassword({ repoName, currentPassword, newPassword }, { sessionToken })
  -> {}
```

Behavior:

- re-wraps DEK with new KEK according to repository format spec

#### deleteRepository

```text
deleteRepository({ repoName }, { sessionToken })
  -> {}
```

### 5.2 Secret Operations

#### addSecret

```text
addSecret({ repoName, type, title, notes?, typeFields... }, { sessionToken })
  -> SecretSummary
```

#### listSecrets

```text
listSecrets({ repoName }, { sessionToken })
  -> { items: SecretSummary[] }
```

#### searchSecretsByTitle

```text
searchSecretsByTitle({ repoName, titleQuery }, { sessionToken })
  -> { items: SecretSummary[] }
```

Matching rule (v1):

- case-insensitive substring match

#### getSecretById

```text
getSecretById({ repoName, secretId, maskSecuredFields = true }, { sessionToken })
  -> SecretRecord
```

#### getSecretByTitle

```text
getSecretByTitle({ repoName, title, maskSecuredFields = true }, { sessionToken })
  -> SecretRecord
```

#### updateSecret

```text
updateSecret({ repoName, secretId, patch }, { sessionToken })
  -> SecretSummary
```

Patch rules:

- partial update allowed
- type cannot be changed in v1
- title uniqueness must remain true
- user cannot update `id` or `createdAt`
- user cannot directly update `updatedAt`; it is program-managed

#### deleteSecret

```text
deleteSecret({ repoName, secretId }, { sessionToken })
  -> {}
```

## 6. Output Shapes

### 6.1 SecretSummary

```json
{
  "id": "sec_01...",
  "type": "password",
  "title": "GitHub",
  "createdAt": "2026-07-20T10:01:00Z",
  "updatedAt": "2026-07-20T10:02:00Z"
}
```

### 6.2 SecretRecord Masking Rule

In v1, only `password` field in `password` type is secured.

- if maskSecuredFields=true: password value is masked (for example `********`)
- if maskSecuredFields=false: password value is returned as stored plaintext in decrypted memory context

## 7. Error Model

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

## 8. Adapter Mapping

### 8.1 CLI to Core

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

### 8.2 HTTP to Core

Examples:

- POST /v1/repos -> createRepository
- POST /v1/repos/{repoName}/unlock -> unlockRepository
- POST /v1/repos/{repoName}/secrets -> addSecret
- GET /v1/repos/{repoName}/secrets/{id} -> getSecretById

HTTP adapter responsibilities:

- parse/validate transport JSON
- pass bearer token as sessionToken context
- map CoreError to HTTP status + error body

## 9. Invariants and Security Constraints

- core never stores masterPassword after operation completes
- repository writes are atomic
- repository format validation is mandatory before decrypt
- decrypt/search happens in memory only
- no plaintext secret fields in logs

## 10. Compatibility

- this contract is v1 and additive-first
- breaking changes require version bump and migration notes
- adapters must remain backward-compatible within major version
