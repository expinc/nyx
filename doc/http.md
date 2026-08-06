# HTTP Reference

This document describes how to use Nyx through its HTTP interface.

- [Base URL and Conventions](#base-url-and-conventions)
- [Authentication and Session](#authentication-and-session)
- [Repository Lifecycle](#repository-lifecycle)
    - [Create Repository](#create-repository)
    - [Unlock Repository](#unlock-repository)
    - [Lock Repository](#lock-repository)
    - [Repository Status](#repository-status)
    - [Change Master Password](#change-master-password)
    - [Delete Repository](#delete-repository)
- [Secret Lifecycle](#secret-lifecycle)
    - [Add Secret](#add-secret)
    - [List Secrets](#list-secrets)
    - [Search Secrets by Title](#search-secrets-by-title)
    - [Read Secret](#read-secret)
    - [Update Secret](#update-secret)
    - [Remove Secret](#remove-secret)
- [Error Format](#error-format)

## Base URL and Conventions

Default base URL:

```text
http://127.0.0.1:8080
```

HTTPS may be enabled depending on server configuration.

Common conventions:

- Request and response bodies are JSON (`application/json`).
- Repository is identified by `repoName`.
- Timestamps use UTC ISO 8601 format.

## Authentication and Session

Nyx HTTP APIs use an auth session token after repository unlock.

Flow:

1. Call unlock endpoint with `repoName` and `masterPassword`.
2. Receive `sessionToken` and `expiresAt`.
3. Send token on subsequent requests:

```text
Authorization: Bearer <sessionToken>
```

Notes:

- Sessions are short-lived local sessions.
- Locking a repository invalidates only the current session token.
- Other active HTTP sessions on the same repository remain valid.
- If token is missing/expired, APIs return authentication error.

## Repository Lifecycle

### Create Repository

`POST /v1/repos`

Request:

```json
{
	"repoName": "personal",
	"masterPassword": "<password>"
}
```

Response `201 Created`:

```json
{
	"repoName": "personal",
	"createdAt": "2026-07-20T10:00:00Z"
}
```

### Unlock Repository

`POST /v1/repos/{repoName}/unlock`

Request:

```json
{
	"masterPassword": "<password>"
}
```

Response `200 OK`:

```json
{
	"repoName": "personal",
	"sessionToken": "nyx_sess_xxx",
	"expiresAt": "2026-07-20T10:15:00Z"
}
```

### Lock Repository

`POST /v1/repos/{repoName}/lock`

Response `204 No Content`

### Repository Status

`GET /v1/repos/{repoName}`

Response `200 OK`:

```json
{
	"repoName": "personal",
	"locked": false,
	"secretCount": 3,
	"updatedAt": "2026-07-20T10:05:00Z"
}
```

### Change Master Password

`POST /v1/repos/{repoName}/change-password`

Request:

```json
{
	"currentPassword": "<current>",
	"newPassword": "<new>"
}
```

Response `204 No Content`

### Delete Repository

`DELETE /v1/repos/{repoName}`

Response `204 No Content`

## Secret Lifecycle

### Add Secret

`POST /v1/repos/{repoName}/secrets`

Password secret:

```json
{
	"type": "password",
	"title": "GitHub",
	"notes": "personal account",
    "name": "alice@example.com",
    "password": "<secret>"
}
```

Certificate secret:

```json
{
	"type": "certificate",
	"title": "Prod TLS",
    "certificate": "-----BEGIN CERTIFICATE-----...",
    "privateKey": "-----BEGIN PRIVATE KEY-----..."
}
```

Information secret:

```json
{
	"type": "information",
	"title": "Recovery Contact",
    "content": "Call +1-555-0100 during incident"
}
```

Response `201 Created`:

```json
{
	"id": "sec_01JABCDEF123",
	"title": "GitHub",
	"type": "password",
	"createdAt": "2026-07-20T10:01:00Z",
	"updatedAt": "2026-07-20T10:01:00Z"
}
```

### List Secrets

`GET /v1/repos/{repoName}/secrets`

Response `200 OK`:

```json
{
	"items": [
		{
			"id": "sec_01JABCDEF123",
			"title": "GitHub",
			"type": "password",
			"createdAt": "2026-07-20T10:01:00Z",
			"updatedAt": "2026-07-20T10:01:00Z"
		}
	]
}
```

### Search Secrets by Title

`GET /v1/repos/{repoName}/secrets/search?title=git`

Response `200 OK`:

```json
{
	"items": [
		{
			"id": "sec_01JABCDEF123",
			"title": "GitHub",
			"type": "password"
		}
	]
}
```

### Read Secret

Read by ID:

`GET /v1/repos/{repoName}/secrets/sec_01JABCDEF123`

Response `200 OK`:

```json
{
	"id": "sec_01JABCDEF123",
	"type": "password",
	"title": "GitHub",
	"notes": "personal account",
	"createdAt": "2026-07-20T10:01:00Z",
	"updatedAt": "2026-07-20T10:02:00Z",
    "name": "alice@example.com",
    "password": "********"
}
```

### Update Secret

`PATCH /v1/repos/{repoName}/secrets/sec_01JABCDEF123`

Constraints:

- updating on `id` or `createdAt` has no effect
- `updatedAt` is set by Nyx automatically and cannot be set by client

Update title/notes:

```json
{
	"title": "GitHub Personal",
	"notes": "rotated on 2026-07-16"
}
```

Update password field:

```json
{
    "name": "New name",
    "password": "<new-secret>"
}
```

Update certificate fields:

```json
{
    "certificate": "-----BEGIN CERTIFICATE-----...",
    "privateKey": "-----BEGIN PRIVATE KEY-----..."
}
```

Update information fields:

```json
{
    "content": "New content"
}
```

Response `200 OK` returns updated secret summary.

### Remove Secret

`DELETE /v1/repos/{repoName}/secrets/sec_01JABCDEF123`

Response `204 No Content`

## Error Format

Error response body:

```json
{
	"error": {
		"message": "Error message",
		"details": {}
	}
}
```
