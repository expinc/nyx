package session

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestEnsureSessionLayoutCreatesBaseDirectories(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	if err := ensureSessionLayout(dataDir); err != nil {
		t.Fatalf("ensureSessionLayout failed: %v", err)
	}

	root := filepath.Join(dataDir, sessionRootDirName)
	for _, path := range []string{
		root,
		filepath.Join(root, cliModeDirName),
		filepath.Join(root, httpModeDirName),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("expected %s to exist: %v", path, err)
		}
		if !info.IsDir() {
			t.Fatalf("expected %s to be directory", path)
		}
	}
}

func TestSessionPathLayout(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	repoHash := "abc123"
	sessionID := "sess_id"

	cliPath, err := cliSessionPath(dataDir, repoHash)
	if err != nil {
		t.Fatalf("cliSessionPath failed: %v", err)
	}
	if want := filepath.Join(dataDir, sessionRootDirName, cliModeDirName, repoHash+sessionFileSuffix); cliPath != want {
		t.Fatalf("unexpected cli path: got %s, want %s", cliPath, want)
	}

	httpPath, err := httpSessionPath(dataDir, repoHash, sessionID)
	if err != nil {
		t.Fatalf("httpSessionPath failed: %v", err)
	}
	if want := filepath.Join(dataDir, sessionRootDirName, httpModeDirName, repoHash, sessionID+sessionFileSuffix); httpPath != want {
		t.Fatalf("unexpected http path: got %s, want %s", httpPath, want)
	}
}

func TestWriteReadSessionRecordRoundTrip(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	if err := ensureSessionLayout(dataDir); err != nil {
		t.Fatalf("ensureSessionLayout failed: %v", err)
	}

	repoHash := "abc123"
	if _, err := ensureHTTPSessionsRepoDir(dataDir, repoHash); err != nil {
		t.Fatalf("ensureHTTPSessionsRepoDir failed: %v", err)
	}

	path, err := httpSessionPath(dataDir, repoHash, "sess_1")
	if err != nil {
		t.Fatalf("httpSessionPath failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	rec := Record{
		Version:   SessionRecordVersion,
		Mode:      ModeHTTP,
		RepoName:  "personal",
		SessionID: "sess_1",
		TokenHash: "sha256:deadbeef",
		CreatedAt: now,
		ExpiresAt: now.Add(5 * time.Minute),
	}

	if err := writeSessionRecord(path, rec); err != nil {
		t.Fatalf("writeSessionRecord failed: %v", err)
	}

	got, err := readSessionRecord(path)
	if err != nil {
		t.Fatalf("readSessionRecord failed: %v", err)
	}

	if got.Mode != rec.Mode || got.RepoName != rec.RepoName || got.SessionID != rec.SessionID || got.TokenHash != rec.TokenHash {
		t.Fatalf("record mismatch after roundtrip: got %+v want %+v", got, rec)
	}
	if !got.CreatedAt.Equal(rec.CreatedAt) {
		t.Fatalf("createdAt mismatch: got %s want %s", got.CreatedAt, rec.CreatedAt)
	}
	if !got.ExpiresAt.Equal(rec.ExpiresAt) {
		t.Fatalf("expiresAt mismatch: got %s want %s", got.ExpiresAt, rec.ExpiresAt)
	}
}

func TestWriteReadCLISessionRecordRoundTrip(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	if err := ensureSessionLayout(dataDir); err != nil {
		t.Fatalf("ensureSessionLayout failed: %v", err)
	}

	path, err := cliSessionPath(dataDir, "abc123")
	if err != nil {
		t.Fatalf("cliSessionPath failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	rec := Record{
		Version:   SessionRecordVersion,
		Mode:      ModeCLI,
		RepoName:  "personal",
		SessionID: "sess_cli_1",
		CreatedAt: now,
		ExpiresAt: now.Add(5 * time.Minute),
	}

	if err := writeSessionRecord(path, rec); err != nil {
		t.Fatalf("writeSessionRecord failed: %v", err)
	}

	got, err := readSessionRecord(path)
	if err != nil {
		t.Fatalf("readSessionRecord failed: %v", err)
	}

	if got.Mode != rec.Mode || got.RepoName != rec.RepoName || got.SessionID != rec.SessionID {
		t.Fatalf("record mismatch after roundtrip: got %+v want %+v", got, rec)
	}
	if got.TokenHash != "" {
		t.Fatalf("expected empty tokenHash for CLI mode, got %q", got.TokenHash)
	}
	if !got.CreatedAt.Equal(rec.CreatedAt) {
		t.Fatalf("createdAt mismatch: got %s want %s", got.CreatedAt, rec.CreatedAt)
	}
	if !got.ExpiresAt.Equal(rec.ExpiresAt) {
		t.Fatalf("expiresAt mismatch: got %s want %s", got.ExpiresAt, rec.ExpiresAt)
	}
}

func TestReadSessionRecordMalformedLeavesArtifact(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	if err := ensureSessionLayout(dataDir); err != nil {
		t.Fatalf("ensureSessionLayout failed: %v", err)
	}

	path, err := cliSessionPath(dataDir, "hash1")
	if err != nil {
		t.Fatalf("cliSessionPath failed: %v", err)
	}

	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatalf("failed to seed malformed session file: %v", err)
	}

	if _, err := readSessionRecord(path); err == nil {
		t.Fatal("expected readSessionRecord to fail for malformed content")
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected malformed artifact to remain for caller cleanup, stat err=%v", err)
	}
}

func TestReadSessionRecordInvalidMode(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	if err := ensureSessionLayout(dataDir); err != nil {
		t.Fatalf("ensureSessionLayout failed: %v", err)
	}

	path, err := cliSessionPath(dataDir, "hashmode")
	if err != nil {
		t.Fatalf("cliSessionPath failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	rec := Record{
		Version:   SessionRecordVersion,
		Mode:      "invalid",
		RepoName:  "personal",
		SessionID: "sess_bad_mode",
		CreatedAt: now,
		ExpiresAt: now.Add(5 * time.Minute),
	}
	if err := writeSessionRecord(path, rec); err != nil {
		t.Fatalf("writeSessionRecord failed: %v", err)
	}

	if _, err := readSessionRecord(path); err == nil {
		t.Fatal("expected readSessionRecord to fail for invalid mode")
	}
}

func TestListHTTPSessionFiles(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	repoHash := "repohash"
	if err := ensureSessionLayout(dataDir); err != nil {
		t.Fatalf("ensureSessionLayout failed: %v", err)
	}
	dir, err := ensureHTTPSessionsRepoDir(dataDir, repoHash)
	if err != nil {
		t.Fatalf("ensureHTTPSessionsRepoDir failed: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "a"+sessionFileSuffix), []byte("{}"), 0o600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	files, err := listHTTPSessionFiles(dataDir, repoHash)
	if err != nil {
		t.Fatalf("listHTTPSessionFiles failed: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected one session file, got %d", len(files))
	}
	if filepath.Base(files[0]) != "a"+sessionFileSuffix {
		t.Fatalf("unexpected file listed: %s", files[0])
	}
}

func TestSessionPermissionsPlatformAware(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	if err := ensureSessionLayout(dataDir); err != nil {
		t.Fatalf("ensureSessionLayout failed: %v", err)
	}

	repoHash := "permhash"
	if _, err := ensureHTTPSessionsRepoDir(dataDir, repoHash); err != nil {
		t.Fatalf("ensureHTTPSessionsRepoDir failed: %v", err)
	}

	cliPath, err := cliSessionPath(dataDir, repoHash)
	if err != nil {
		t.Fatalf("cliSessionPath failed: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	rec := Record{
		Version:   SessionRecordVersion,
		Mode:      ModeCLI,
		RepoName:  "personal",
		SessionID: "sess_perm",
		CreatedAt: now,
		ExpiresAt: now.Add(5 * time.Minute),
	}
	if err := writeSessionRecord(cliPath, rec); err != nil {
		t.Fatalf("writeSessionRecord failed: %v", err)
	}

	if runtime.GOOS == "windows" {
		if _, err := os.Stat(cliPath); err != nil {
			t.Fatalf("expected session file to exist on windows: %v", err)
		}
		return
	}

	root := filepath.Join(dataDir, sessionRootDirName)
	cliDir := filepath.Join(root, cliModeDirName)
	httpDir := filepath.Join(root, httpModeDirName)
	repoDir := filepath.Join(httpDir, repoHash)

	for _, dir := range []string{root, cliDir, httpDir, repoDir} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("expected directory %s to exist: %v", dir, err)
		}
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Fatalf("unexpected directory permissions for %s: got %o want 700", dir, perm)
		}
	}

	info, err := os.Stat(cliPath)
	if err != nil {
		t.Fatalf("expected session file to exist: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("unexpected session file permissions: got %o want 600", perm)
	}
}
