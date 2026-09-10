package session

import "time"

const (
	ModeCLI  = "cli"
	ModeHTTP = "http"

	SessionRecordVersion = 1
)

// Record is the persisted session schema.
type Record struct {
	Version   int       `json:"version"`
	Mode      string    `json:"mode"`
	RepoName  string    `json:"repoName"`
	SessionID string    `json:"sessionId"`
	TokenHash string    `json:"tokenHash,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type CreateSessionResult struct {
	Mode      string
	RepoName  string
	SessionID string
	Token     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type ValidationResult struct {
	Mode      string
	RepoName  string
	SessionID string
	ExpiresAt time.Time
	Valid     bool
}
