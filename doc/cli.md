# CLI Reference

This document describes how to use Nyx from the command line to manage the full lifecycle of repositories and secrets.

- [Command Layout](#command-layout)
- [Repository Lifecycle](#repository-lifecycle)
    - [Create](#create)
    - [Unlock](#unlock)
    - [Lock](#lock)
    - [Status](#status)
    - [Change Master Password](#change-master-password)
    - [Delete](#delete)
- [Secret Lifecycle](#secret-lifecycle)
    - [Add Secret](#add-secret)
    - [List Secrets](#list-secrets)
    - [Search Secrets by Title](#search-secrets-by-title)
    - [Read Secret](#read-secret)
    - [Update Secret](#update-secret)
    - [Remove Secret](#remove-secret)

## Command Layout

Nyx commands follow this pattern:

```bash
nyx <group> <command> [options]
```

Main command groups:

- `repo`: repository lifecycle operations
- `secret`: secret lifecycle operations

Global options:

- `--repo <path>`: repository file path (required for most commands)
- `--format <table|json>`: output format for list/read commands
- `--no-mask`: show secured fields in output (use with care)
- `--yes`: skip interactive confirmation for destructive commands
- `--help`: show help for any command

Repository identity and `repoName` derivation rules are defined in [the core API documentation](core_api.md).

## Repository Lifecycle

### Create

Create a new encrypted repository file with a master password.

```bash
nyx repo create --repo ./vault.nyx
```

Behavior:

- prompts for master password (hidden input)
- creates repository file atomically
- fails if file already exists

### Unlock

Unlock repository for subsequent secret operations.

```bash
nyx repo unlock --repo ./vault.nyx
```

Behavior:

- prompts for master password (hidden input)
- validates password-derived metadata
- opens a local session

### Lock

Lock the currently unlocked repository session.

```bash
nyx repo lock --repo ./vault.nyx
```

### Status

Show repository status.

```bash
nyx repo status --repo ./vault.nyx
```

Typical output includes:

- repository name
- locked/unlocked state
- secret count
- last updated timestamp

### Change Master Password

Rotate repository master password.

```bash
nyx repo change-password --repo ./vault.nyx
```

Behavior:

- prompts for current password
- prompts for new password and confirmation
- re-encrypts repository metadata/data key material

### Delete

Delete repository file permanently.

```bash
nyx repo delete --repo ./vault.nyx
nyx repo delete --repo ./vault.nyx --yes
```

## Secret Lifecycle

### Add Secret

Create a new secret with typed fields.

Password secret:

```bash
nyx secret add password \
	--repo ./vault.nyx \
	--title "GitHub" \
	--name "My name" \
	--password "<prompt-if-omitted>" \
	--notes "personal account"
```

Certificate secret:

```bash
nyx secret add certificate \
	--repo ./vault.nyx \
	--title "Prod TLS" \
	--certificate ./tls.crt \
	--private-key ./tls.key
```

Information secret:

```bash
nyx secret add information \
	--repo ./vault.nyx \
	--title "Recovery Contact" \
	--content "Call +1-555-0100 during incident"
```

Notes:

- if `--password` is omitted for `password` type, Nyx prompts securely

### List Secrets

List secrets (summary output).

```bash
nyx secret list --repo ./vault.nyx
nyx secret list --repo ./vault.nyx --format json
```

### Search Secrets by Title

Search secrets by title substring.

```bash
nyx secret search --repo ./vault.nyx --title "git"
```

### Read Secret

Read full secret by ID or title.

```bash
nyx secret get --repo ./vault.nyx --id sec_01JABCDEF123
nyx secret get --repo ./vault.nyx --id sec_01JABCDEF123 --no-mask
nyx secret get --repo ./vault.nyx --title "My secret"
nyx secret get --repo ./vault.nyx --title "My secret" --no-mask
```

Default behavior masks secured fields.

### Update Secret

Update secret metadata or type-specific fields.

Constraints:

- `id` and `createdAt` cannot be updated by user commands. Attempts to update them are ignored.
- `updatedAt` is managed by Nyx and updated automatically

Update title/notes:

```bash
nyx secret update --repo ./vault.nyx --id sec_01JABCDEF123 \
	--title "GitHub Personal" \
	--notes "rotated on 2026-07-16"
```

Update password fields:

```bash
nyx secret update --repo ./vault.nyx --id sec_01JABCDEF123 --name "My name" --password "<prompt-if-omitted>"
```

Update certificate fields:

```bash
nyx secret update --repo ./vault.nyx --id sec_01JABCDEFAAA \
	--certificate ./new.crt \
	--private-key ./new.key
```

Update information fields:

```bash
nyx secret update --repo ./vault.nyx --id sec_01JABCDEF123 --content "New content"
```

### Remove Secret

Delete secret by ID.

```bash
nyx secret delete --repo ./vault.nyx --id sec_01JABCDEF123
nyx secret delete --repo ./vault.nyx --id sec_01JABCDEF123 --yes
```
