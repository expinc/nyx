# Nyx Session Management Specification

## 1. Purpose and Scope

This document defines how Nyx manage lock/unlock session state.

It applies to both CLI and HTTP flows and complements:

- [doc/core_api.md](core_api.md)
- [doc/cli.md](cli.md)
- [doc/http.md](http.md)

Out of scope:

- Daemon-based session management.
- OS-specific secure storage integration.
- Repository file format details (covered by [doc/repository_format.md](repository_format.md)).

## 2. Design Decisions (v1)

- CLI commands run as independent processes; session state must be persisted locally.
- No daemon is used.
- No OS-specific secure storage (for example Keychain) is required.
- Session persistence is short-lived local caching with explicit security tradeoff.
- HTTP supports multiple active sessions on the same repository.
- CLI keeps a single active session per repository.
- Concurrent session coordination between CLI and HTTP for the same repository is out of scope in v1.

## 3. Security Requirements

- Session state must be repository-scoped.
- Sessions must expire automatically (TTL-based).
- Lock operation must revoke session immediately.
- Session files must use least-privilege file permissions.
- Sensitive values must not be logged.

## 4. Storage Location

Nyx stores session files under a runtime data directory:

```text
<nyxDataDir>/sessions/
```

- `nyxDataDir` is fixed by platform in v1.
- `sessions` directory is created if missing.

Default `nyxDataDir` (v1):

- Linux: `~/.nyx`
- macOS: `~/Library/Application Support/nyx`
- Windows: `%AppData%\\nyx`

Fallback behavior:

- If the platform-specific path cannot be resolved, Nyx must fail with a clear startup error.

Permission guidance:

- Directory: owner only (for example 0700 on POSIX).
- Session files: owner read/write only (for example 0600 on POSIX).

## 5. Session Identity Model

- Repository identity is based on exact `repoName` string (case-sensitive in v1).
- Session storage is mode-specific.

Mode-specific identity model:

- CLI: one active session per repository name.
- HTTP: multiple active sessions per repository name.

File naming:

- CLI: `cli/<repoNameHash>.session.json`
- HTTP: `http/<repoNameHash>/<sessionId>.session.json`

Where `repoNameHash` is SHA-256 hex of canonical repo name bytes.

## 6. Session Record Schema (v1)

Session file format is UTF-8 JSON.

```json
{
  "version": 1,
  "mode": "http",
  "repoName": "personal",
  "sessionId": "sess_01...",
  "tokenHash": "sha256:...",
  "createdAt": "2026-08-06T10:00:00Z",
  "expiresAt": "2026-08-06T10:15:00Z"
}
```

Field rules:

- `version`: schema version of session record.
- `mode`: `cli` or `http`.
- `repoName`: repository name this session belongs to.
- `sessionId`: generated session identifier.
- `tokenHash`: hash of HTTP bearer token value; raw token is not persisted. This field is optional for CLI-origin sessions.
- `createdAt`, `expiresAt`: UTC ISO 8601 timestamps.

Mode-specific identity usage:

- CLI: session identity is repository-scoped (`repoName` + expiration). `tokenHash` may be empty or omitted.
- HTTP: session identity is session-scoped (`repoName` + `sessionId` + expiration + `tokenHash` match).

## 7. Lifecycle Semantics

### Unlock

On successful unlock:

1. Create session record with fresh `sessionId` and `expiresAt`.
2. For HTTP-origin unlock, generate and return a raw session token and persist only `tokenHash`.
3. For CLI-origin unlock, no raw token is required in user interaction.
4. Persist session record atomically.

Mode-specific unlock behavior:

- CLI: replace any existing CLI session record for the same repository.
- HTTP: append a new HTTP session record for the repository (do not replace other HTTP sessions).

### Session Validation

A session is valid only if all are true:

1. Session file exists and parses successfully.
2. `repoName` matches target repository.
3. Current time is before `expiresAt`.
4. HTTP mode: provided token matches `tokenHash`.
5. CLI mode: token check is not required.

### Lock

On lock request:

1. CLI mode: delete CLI session record for repository.
2. HTTP mode: delete only the current HTTP session record identified by token/session.
3. If target session record is missing, operation is idempotent success.

### Expiration

- Expired sessions are treated as invalid.
- Expired records should be removed opportunistically during normal operations.

## 8. Atomicity and Corruption Handling

Write operations must be atomic:

1. Write temporary file in same directory.
2. fsync temporary file.
3. Rename over target session file.

Read behavior:

- If session file is malformed, treat session as invalid.
- Attempt cleanup of malformed record.
- Return safe authentication/session error without sensitive details.

## 9. Concurrency Behavior

- Session update and delete operations should be race-safe for concurrent Nyx processes.
- CLI unlock for the same repository replaces previous CLI session record.
- HTTP unlock for the same repository creates additional HTTP session records.
- HTTP lock revokes only the current HTTP session record; other HTTP sessions on the same repository remain valid.
- Concurrent session coordination between CLI and HTTP on the same repository is out of scope in v1.

## 10. Defaults and Configuration

Recommended defaults:

- Session TTL: 5 minutes.
- Session storage enabled by default for cross-process usability.

Configurable settings:

- session TTL duration
- optional disable session caching mode

## 11. Explicit Tradeoffs

- Without daemon and without OS-secure storage, session persistence in local files is a usability/security tradeoff.
- v1 favors portability and simplicity, with short TTL and strict permissions to reduce risk.
