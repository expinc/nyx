package session

import (
	"path/filepath"
	"strings"
)

const (
	sessionRootDirName = "sessions"
	cliModeDirName     = "cli"
	httpModeDirName    = "http"
	sessionFileSuffix  = ".session.json"
)

func sessionsRootPath(dataDir string) (string, error) {
	if dataDir == "" {
		return "", NewInvalidArgumentError("dataDir is required", nil)
	}

	return filepath.Join(dataDir, sessionRootDirName), nil
}

func cliSessionPath(dataDir, repoNameHash string) (string, error) {
	if err := validatePathSegment(repoNameHash); err != nil {
		return "", err
	}

	root, err := sessionsRootPath(dataDir)
	if err != nil {
		return "", err
	}

	return filepath.Join(root, cliModeDirName, repoNameHash+sessionFileSuffix), nil
}

func httpSessionPath(dataDir, repoNameHash, sessionID string) (string, error) {
	if err := validatePathSegment(repoNameHash); err != nil {
		return "", err
	}
	if err := validatePathSegment(sessionID); err != nil {
		return "", err
	}

	root, err := sessionsRootPath(dataDir)
	if err != nil {
		return "", err
	}

	return filepath.Join(root, httpModeDirName, repoNameHash, sessionID+sessionFileSuffix), nil
}

func httpSessionsRepoDir(dataDir, repoNameHash string) (string, error) {
	if err := validatePathSegment(repoNameHash); err != nil {
		return "", err
	}

	root, err := sessionsRootPath(dataDir)
	if err != nil {
		return "", err
	}

	return filepath.Join(root, httpModeDirName, repoNameHash), nil
}

func validatePathSegment(v string) error {
	if v == "" {
		return NewInvalidArgumentError("path segment is required", nil)
	}
	if strings.Contains(v, "/") || strings.Contains(v, "\\") {
		return NewInvalidArgumentError("path segment must not contain path separators", nil)
	}

	return nil
}
