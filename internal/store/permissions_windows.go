//go:build windows

package store

import "os"

func setRepositoryFilePermissions(f *os.File) error {
	// TODO(windows-permissions): implement explicit ACL restriction for repository files.
	// For now, keep the same best-effort mode call used elsewhere. On Windows this does
	// not provide POSIX-equivalent 0600 semantics and mainly maps to file attributes.
	// Effective access control currently depends on parent directory ACL inheritance.
	_ = f.Chmod(0o600)
	return nil
}
