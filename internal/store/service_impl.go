package store

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"nyx/internal/model/repoenc"
)

type service struct{}

func (s *service) Load(path string) (repoenc.Repository, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return repoenc.Repository{}, NewNotFoundError("repository file not found", err)
		}
		return repoenc.Repository{}, NewReadFailedError("failed to read repository file", err)
	}

	repo, err := ParseRepositoryJSON(data)
	if err != nil {
		return repoenc.Repository{}, err
	}
	return repo, nil
}

func (s *service) Save(path string, repo repoenc.Repository) error {
	data, err := RenderRepositoryJSON(repo)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return NewWriteFailedError("failed to create temporary repository file", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := setRepositoryFilePermissions(tmp); err != nil {
		_ = tmp.Close()
		return NewWriteFailedError("failed to set repository file permissions", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return NewWriteFailedError("failed to write repository data", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return NewWriteFailedError("failed to sync repository temp file", err)
	}
	if err := tmp.Close(); err != nil {
		return NewWriteFailedError("failed to close repository temp file", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return NewWriteFailedError("failed to atomically replace repository file", err)
	}
	tmpPath = ""

	if err := syncDirectory(dir); err != nil {
		return NewWriteFailedError("failed to sync repository directory", err)
	}
	return nil
}

func (s *service) Exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, NewReadFailedError("failed to check repository file", err)
}

// syncDirectory attempts to flush directory metadata after atomic rename.
// This improves durability of the rename step on platforms/filesystems that
// support directory fsync. If directory sync is not implemented/supported,
// we treat it as best-effort and allow the save operation to succeed.
func syncDirectory(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()

	if err := d.Sync(); err != nil {
		// Some platforms/filesystems do not support syncing directory handles.
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.ENOSYS) {
			return nil
		}
		return err
	}
	return nil
}
