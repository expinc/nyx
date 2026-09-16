package session

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func hashRepoName(repoName string) (string, error) {
	if repoName == "" {
		return "", NewInvalidArgumentError("repoName is required", nil)
	}
	if strings.Contains(repoName, "/") || strings.Contains(repoName, "\\") {
		return "", NewInvalidArgumentError("repoName must not contain path separators", nil)
	}

	sum := sha256.Sum256([]byte(repoName))
	return hex.EncodeToString(sum[:]), nil
}
