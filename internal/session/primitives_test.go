package session

import (
	"strings"
	"testing"
)

func TestHashRepoName_Deterministic(t *testing.T) {
	t.Parallel()

	h1, err := hashRepoName("personal")
	if err != nil {
		t.Fatalf("hashRepoName returned error: %v", err)
	}

	h2, err := hashRepoName("personal")
	if err != nil {
		t.Fatalf("hashRepoName returned error on second call: %v", err)
	}

	if h1 != h2 {
		t.Fatalf("expected deterministic hash, got %q and %q", h1, h2)
	}
	// SHA-256 is 32 bytes and hex encodes each byte as 2 characters.
	if len(h1) != 64 {
		t.Fatalf("expected sha256 hex length 64, got %d", len(h1))
	}
}

func TestHashRepoName_Invalid(t *testing.T) {
	t.Parallel()

	if _, err := hashRepoName(""); err == nil {
		t.Fatalf("expected error for empty repoName")
	}
	if _, err := hashRepoName("a/b"); err == nil {
		t.Fatalf("expected error for slash")
	}
	if _, err := hashRepoName("a\\b"); err == nil {
		t.Fatalf("expected error for backslash")
	}
}

func TestGenerateSessionID_Format(t *testing.T) {
	t.Parallel()

	id, err := generateSessionID()
	if err != nil {
		t.Fatalf("generateSessionID returned error: %v", err)
	}

	if !strings.HasPrefix(id, sessionIDPrefix) {
		t.Fatalf("expected prefix %q, got %q", sessionIDPrefix, id)
	}
	if len(id) <= len(sessionIDPrefix) {
		t.Fatalf("expected non-empty random segment")
	}
}

func TestGenerateSessionToken_Format(t *testing.T) {
	t.Parallel()

	token, err := generateSessionToken()
	if err != nil {
		t.Fatalf("generateSessionToken returned error: %v", err)
	}

	if !strings.HasPrefix(token, sessionTokenPrefix) {
		t.Fatalf("expected prefix %q, got %q", sessionTokenPrefix, token)
	}
	if len(token) <= len(sessionTokenPrefix) {
		t.Fatalf("expected non-empty random segment")
	}
}
func TestHashTokenAndMatch(t *testing.T) {
	t.Parallel()

	token := "st_example_token"
	hash, err := hashToken(token)
	if err != nil {
		t.Fatalf("hashToken returned error: %v", err)
	}

	if !strings.HasPrefix(hash, tokenHashPrefix) {
		t.Fatalf("expected token hash prefix %q, got %q", tokenHashPrefix, hash)
	}
	if strings.Contains(hash, token) {
		t.Fatalf("hash must not contain raw token")
	}

	if !tokenHashMatches(token, hash) {
		t.Fatalf("expected token hash to match")
	}
	if tokenHashMatches(token+"x", hash) {
		t.Fatalf("expected token hash mismatch for different token")
	}
	if tokenHashMatches(token, "md5:deadbeef") {
		t.Fatalf("expected token hash mismatch for invalid hash prefix")
	}
}

func TestHashToken_Empty(t *testing.T) {
	t.Parallel()

	if _, err := hashToken(""); err == nil {
		t.Fatalf("expected error for empty token")
	}
}
