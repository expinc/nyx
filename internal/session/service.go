package session

import "time"

// Service defines local unlock-session lifecycle operations.
type Service interface {
	CreateCLISession(repoName string) (CreateSessionResult, error)
	CreateHTTPSession(repoName string) (CreateSessionResult, error)

	ValidateCLISession(repoName string) error
	ValidateHTTPSession(repoName, token string) error

	RevokeCLISession(repoName string) error
	RevokeHTTPSession(repoName, sessionID, token string) error

	Cleanup(repoName string) error
}

// Config configures session service behavior.
type Config struct {
	DataDir    string
	SessionTTL time.Duration
}

func NewService(cfg Config) Service {
	return &service{cfg: cfg, nowFn: time.Now}
}
