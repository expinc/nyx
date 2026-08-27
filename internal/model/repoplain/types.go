package repoplain

import (
	"fmt"
	"time"
)

const (
	SecretTypePassword    = "password"
	SecretTypeCertificate = "certificate"
	SecretTypeInformation = "information"
)

// RepositoryContent is the decrypted repository payload model.
type RepositoryContent struct {
	SchemaVersion int       `json:"schemaVersion"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
	Secrets       []Secret  `json:"secrets"`
}

// Secret is a union-style record for v1 payload secret entries.
type Secret struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Title     string    `json:"title"`
	Notes     string    `json:"notes,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	Name        string `json:"name,omitempty"`
	Password    string `json:"password,omitempty"`
	Certificate string `json:"certificate,omitempty"`
	PrivateKey  string `json:"privateKey,omitempty"`
	Content     string `json:"content,omitempty"`
}

func (r RepositoryContent) Validate() error {
	if r.SchemaVersion <= 0 {
		return fmt.Errorf("schemaVersion must be positive")
	}
	if r.CreatedAt.IsZero() || r.UpdatedAt.IsZero() {
		return fmt.Errorf("createdAt and updatedAt are required")
	}
	for i, s := range r.Secrets {
		if err := s.Validate(); err != nil {
			return fmt.Errorf("invalid secret[%d]: %w", i, err)
		}
	}
	return nil
}

func (s Secret) Validate() error {
	if s.ID == "" {
		return fmt.Errorf("id is required")
	}
	if s.Title == "" {
		return fmt.Errorf("title is required")
	}
	if s.CreatedAt.IsZero() || s.UpdatedAt.IsZero() {
		return fmt.Errorf("createdAt and updatedAt are required")
	}
	if s.Type != SecretTypePassword && s.Type != SecretTypeCertificate && s.Type != SecretTypeInformation {
		return fmt.Errorf("invalid secret type")
	}
	switch s.Type {
	case SecretTypePassword:
		if s.Name == "" || s.Password == "" {
			return fmt.Errorf("password secret requires name and password")
		}
	case SecretTypeCertificate:
		if s.Certificate == "" || s.PrivateKey == "" {
			return fmt.Errorf("certificate secret requires certificate and privateKey")
		}
	case SecretTypeInformation:
		if s.Content == "" {
			return fmt.Errorf("information secret requires content")
		}
	}
	return nil
}
