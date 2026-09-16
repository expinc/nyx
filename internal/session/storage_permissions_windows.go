//go:build windows

package session

import "os"

func setSessionDirPermissions(path string) error {
	// TODO(windows-permissions): apply explicit ACL restriction for session directories.
	// Current behavior relies on inherited ACLs; Chmod is kept as best-effort parity.
	_ = os.Chmod(path, 0o700)
	return nil
}

func setSessionFilePermissions(f *os.File) error {
	// TODO(windows-permissions): apply explicit ACL restriction for session files.
	_ = f.Chmod(0o600)
	return nil
}