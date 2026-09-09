//go:build !windows

package store

import "os"

func setRepositoryFilePermissions(f *os.File) error {
	return f.Chmod(0o600)
}
