package session

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

const (
	sessionIDPrefix    = "sess_"
	sessionTokenPrefix = "st_"
	tokenHashPrefix    = "sha256:"

	sessionIDRandomSize    = 16
	sessionTokenRandomSize = 32
)

func generateSessionID() (string, error) {
	b, err := readRandom(sessionIDRandomSize)
	if err != nil {
		return "", NewWriteFailedError("failed to generate session ID", err)
	}

	return sessionIDPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func generateSessionToken() (string, error) {
	b, err := readRandom(sessionTokenRandomSize)
	if err != nil {
		return "", NewWriteFailedError("failed to generate session token", err)
	}

	return sessionTokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(token string) (string, error) {
	if token == "" {
		return "", NewInvalidArgumentError("token is required", nil)
	}

	sum := sha256.Sum256([]byte(token))
	return tokenHashPrefix + hex.EncodeToString(sum[:]), nil
}

func tokenHashMatches(token, persistedTokenHash string) bool {
	if token == "" || !strings.HasPrefix(persistedTokenHash, tokenHashPrefix) {
		return false
	}

	expected, err := hashToken(token)
	if err != nil {
		return false
	}

	if len(expected) != len(persistedTokenHash) {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(expected), []byte(persistedTokenHash)) == 1
}

func readRandom(size int) ([]byte, error) {
	if size <= 0 {
		return nil, NewInvalidArgumentError("random size must be positive", nil)
	}

	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return b, nil
}
