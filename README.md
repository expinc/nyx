# Nyx

Nyx is a local-first secret manager for securely storing and organizing sensitive text data, including login credentials (such as username, password, URL, and notes) and other private information. It lets users add, update, remove, read, list, and search secrets by title through either a CLI or an HTTP server with the same functionality, while keeping each repository in a single password-protected encrypted file on localhost with atomic file updates for safe persistence.

## Usage

Nyx supports two interfaces with equivalent functionality:

- CLI usage and command reference: [doc/cli.md](doc/cli.md)
- HTTP API usage and endpoint reference: [doc/http.md](doc/http.md)

## Data model

A repository is an encrypted container that stores a collection of secrets. The master password is entered by the user to unlock the repository; the repository never stores the password itself, but does store password-derived cryptographic metadata needed to verify and decrypt the data.

Each secret consists of a few text fields. Some fields are marked as secured and should be masked by default in UI output. There are a few common fields shared by all types of secrets (timestamps in UTC ISO 8601):

- ID: Unique identity generated on secret creation. Unable to change since creation.
- Title: Text to display and search for. Unique in a repository.
- Notes: Custom text for additional information.
- CreatedAt: Timestamp when the secret is created. Unable to change since creation.
- UpdatedAt: Timestamp when the secret is last updated. Update automatically.

There are 3 types of secrets: Password, Certificate, Information. Their specific fields are below:

Password:

- Name
- Password (secured)

Certificate:

- Certificate
- Private key

Information:

- Content
