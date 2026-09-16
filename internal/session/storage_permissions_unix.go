//go:build !windows

package session

import "os"

func setSessionDirPermissions(path string) error {
	return os.Chmod(path, 0o700)
}

func setSessionFilePermissions(f *os.File) error {
	return f.Chmod(0o600)
}