package store

import "nyx/internal/model/repoenc"

// Service defines repository persistence and format-mapping operations.
type Service interface {
	Load(path string) (repoenc.Repository, error)
	Save(path string, repo repoenc.Repository) error
	Exists(path string) (bool, error)
}

func NewService() Service {
	return &service{}
}
