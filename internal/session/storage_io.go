package session

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func ensureSessionLayout(dataDir string) error {
	root, err := sessionsRootPath(dataDir)
	if err != nil {
		return err
	}

	for _, dir := range []string{
		root,
		filepath.Join(root, cliModeDirName),
		filepath.Join(root, httpModeDirName),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return NewWriteFailedError("failed to create session directory", err)
		}
		if err := setSessionDirPermissions(dir); err != nil {
			return NewWriteFailedError("failed to set session directory permissions", err)
		}
	}

	return nil
}

func ensureHTTPSessionsRepoDir(dataDir, repoNameHash string) (string, error) {
	dir, err := httpSessionsRepoDir(dataDir, repoNameHash)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", NewWriteFailedError("failed to create repository session directory", err)
	}
	if err := setSessionDirPermissions(dir); err != nil {
		return "", NewWriteFailedError("failed to set repository session directory permissions", err)
	}

	return dir, nil
}

func writeSessionRecord(path string, record Record) error {
	if path == "" {
		return NewInvalidArgumentError("path is required", nil)
	}

	data, err := json.Marshal(record)
	if err != nil {
		return NewWriteFailedError("failed to encode session record", err)
	}
	data = append(data, '\n')

	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return NewWriteFailedError("failed to open session file", err)
	}

	if err := setSessionFilePermissions(f); err != nil {
		_ = f.Close()
		return NewWriteFailedError("failed to set session file permissions", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return NewWriteFailedError("failed to write session record", err)
	}
	if err := f.Close(); err != nil {
		return NewWriteFailedError("failed to close session file", err)
	}

	return nil
}

func readSessionRecord(path string) (Record, error) {
	if path == "" {
		return Record{}, NewInvalidArgumentError("path is required", nil)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Record{}, NewInvalidSessionError("session record not found", err)
		}
		return Record{}, NewReadFailedError("failed to read session file", err)
	}

	var rec Record
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return Record{}, NewInvalidSessionError("invalid session record JSON", err)
	}

	var extra json.RawMessage
	if err := dec.Decode(&extra); err == nil {
		return Record{}, NewInvalidSessionError("session record contains trailing JSON data", nil)
	}

	if err := validateSessionRecordShape(rec); err != nil {
		return Record{}, err
	}

	return rec, nil
}

func validateSessionRecordShape(rec Record) error {
	if rec.Version != SessionRecordVersion {
		return NewInvalidSessionError("unsupported session record version", nil)
	}
	if rec.Mode != ModeCLI && rec.Mode != ModeHTTP {
		return NewInvalidSessionError("invalid session mode", nil)
	}
	if rec.RepoName == "" || rec.SessionID == "" {
		return NewInvalidSessionError("session identity fields are required", nil)
	}
	if rec.CreatedAt.IsZero() || rec.ExpiresAt.IsZero() {
		return NewInvalidSessionError("session timestamps are required", nil)
	}
	if rec.Mode == ModeHTTP && rec.TokenHash == "" {
		return NewInvalidSessionError("tokenHash is required for HTTP sessions", nil)
	}

	return nil
}

func listHTTPSessionFiles(dataDir, repoNameHash string) ([]string, error) {
	dir, err := httpSessionsRepoDir(dataDir, repoNameHash)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, NewReadFailedError("failed to list repository HTTP sessions", err)
	}

	files := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), sessionFileSuffix) {
			continue
		}
		files = append(files, filepath.Join(dir, e.Name()))
	}

	sort.Strings(files)
	return files, nil
}
