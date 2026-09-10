package session

import "time"

// Service defines local unlock-session lifecycle operations.
type Service interface {
	CreateCLISession(repoName string) (CreateSessionResult, error)
	CreateHTTPSession(repoName string) (CreateSessionResult, error)

	ValidateCLISession(repoName string) (ValidationResult, error)
	ValidateHTTPSession(repoName, token string) (ValidationResult, error)

	RevokeCLISession(repoName string) error
	RevokeHTTPSession(repoName, sessionID, token string) error

	Cleanup(repoName string) (int, error)
}

// Config configures session service behavior.
type Config struct {
	DataDir        string
	SessionTTL     time.Duration
	DisableCaching bool
}
