package session

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nyx/internal/common"
)

func TestServiceCLISessionLifecycle(t *testing.T) {
	t.Parallel()

	svc := newTestService(t, Config{DataDir: t.TempDir(), SessionTTL: 5 * time.Minute}, time.Now().UTC())

	created, err := svc.CreateCLISession("personal")
	if err != nil {
		t.Fatalf("CreateCLISession failed: %v", err)
	}
	if created.Mode != ModeCLI || created.Token != "" {
		t.Fatalf("unexpected create result: %+v", created)
	}

	err = svc.ValidateCLISession("personal")
	if err != nil {
		t.Fatalf("ValidateCLISession failed: %v", err)
	}

	if err := svc.RevokeCLISession("personal"); err != nil {
		t.Fatalf("RevokeCLISession failed: %v", err)
	}

	err = svc.ValidateCLISession("personal")
	if err == nil {
		t.Fatal("expected validation failure after revoke")
	}
	assertErrorCode(t, err, ErrCodeInvalidSession)
}

func TestServiceHTTPSessionScopedRevoke(t *testing.T) {
	t.Parallel()

	svc := newTestService(t, Config{DataDir: t.TempDir(), SessionTTL: 5 * time.Minute}, time.Now().UTC())

	a, err := svc.CreateHTTPSession("personal")
	if err != nil {
		t.Fatalf("CreateHTTPSession #1 failed: %v", err)
	}
	b, err := svc.CreateHTTPSession("personal")
	if err != nil {
		t.Fatalf("CreateHTTPSession #2 failed: %v", err)
	}

	if err := svc.ValidateHTTPSession("personal", a.Token); err != nil {
		t.Fatalf("ValidateHTTPSession token A failed: %v", err)
	}
	if err := svc.ValidateHTTPSession("personal", b.Token); err != nil {
		t.Fatalf("ValidateHTTPSession token B failed: %v", err)
	}

	if err := svc.RevokeHTTPSession("personal", a.SessionID, a.Token); err != nil {
		t.Fatalf("RevokeHTTPSession failed: %v", err)
	}

	if err := svc.ValidateHTTPSession("personal", a.Token); err == nil {
		t.Fatal("expected token A to be invalid after revoke")
	}
	if err := svc.ValidateHTTPSession("personal", b.Token); err != nil {
		t.Fatalf("expected token B to remain valid: %v", err)
	}
}

func TestServiceValidateHTTPSessionExpiredCleansArtifact(t *testing.T) {
	t.Parallel()

	base := time.Now().UTC().Truncate(time.Second)
	svc := newTestService(t, Config{DataDir: t.TempDir(), SessionTTL: 5 * time.Minute}, base)

	created, err := svc.CreateHTTPSession("personal")
	if err != nil {
		t.Fatalf("CreateHTTPSession failed: %v", err)
	}

	repoHash, err := hashRepoName("personal")
	if err != nil {
		t.Fatalf("hashRepoName failed: %v", err)
	}
	path, err := httpSessionPath(svc.cfg.DataDir, repoHash, created.SessionID)
	if err != nil {
		t.Fatalf("httpSessionPath failed: %v", err)
	}

	svc.nowFn = func() time.Time { return base.Add(6 * time.Minute) }

	err = svc.ValidateHTTPSession("personal", created.Token)
	if err == nil {
		t.Fatal("expected expired session error")
	}
	assertErrorCode(t, err, ErrCodeSessionExpired)

	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected expired session artifact to be removed, stat err=%v", err)
	}
}

func TestServiceValidateCLISessionMalformedCleansArtifact(t *testing.T) {
	t.Parallel()

	svc := newTestService(t, Config{DataDir: t.TempDir(), SessionTTL: 5 * time.Minute}, time.Now().UTC())
	if err := ensureSessionLayout(svc.cfg.DataDir); err != nil {
		t.Fatalf("ensureSessionLayout failed: %v", err)
	}

	repoHash, err := hashRepoName("personal")
	if err != nil {
		t.Fatalf("hashRepoName failed: %v", err)
	}
	path, err := cliSessionPath(svc.cfg.DataDir, repoHash)
	if err != nil {
		t.Fatalf("cliSessionPath failed: %v", err)
	}
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatalf("failed to seed malformed artifact: %v", err)
	}

	err = svc.ValidateCLISession("personal")
	if err == nil {
		t.Fatal("expected validate error for malformed artifact")
	}
	assertErrorCode(t, err, ErrCodeInvalidSession)

	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected malformed artifact to be cleaned by service, stat err=%v", err)
	}
}

func TestServiceCleanupRemovesMalformedAndExpired(t *testing.T) {
	t.Parallel()

	base := time.Now().UTC().Truncate(time.Second)
	svc := newTestService(t, Config{DataDir: t.TempDir(), SessionTTL: 5 * time.Minute}, base)

	if _, err := svc.CreateCLISession("personal"); err != nil {
		t.Fatalf("CreateCLISession failed: %v", err)
	}
	expired, err := svc.CreateHTTPSession("personal")
	if err != nil {
		t.Fatalf("CreateHTTPSession (expired seed) failed: %v", err)
	}
	valid, err := svc.CreateHTTPSession("personal")
	if err != nil {
		t.Fatalf("CreateHTTPSession (valid seed) failed: %v", err)
	}

	repoHash, err := hashRepoName("personal")
	if err != nil {
		t.Fatalf("hashRepoName failed: %v", err)
	}
	malformedPath, err := httpSessionPath(svc.cfg.DataDir, repoHash, "sess_malformed")
	if err != nil {
		t.Fatalf("httpSessionPath failed: %v", err)
	}
	if err := os.WriteFile(malformedPath, []byte("{broken"), 0o600); err != nil {
		t.Fatalf("failed to seed malformed file: %v", err)
	}

	svc.nowFn = func() time.Time { return base.Add(6 * time.Minute) }
	err = svc.Cleanup("personal")
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	expiredPath, err := httpSessionPath(svc.cfg.DataDir, repoHash, expired.SessionID)
	if err != nil {
		t.Fatalf("httpSessionPath for expired session failed: %v", err)
	}
	if _, err := os.Stat(expiredPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected expired session file deleted, stat err=%v", err)
	}
	if _, err := os.Stat(malformedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected malformed session file deleted, stat err=%v", err)
	}

	err = svc.ValidateHTTPSession("personal", valid.Token)
	if err == nil {
		t.Fatal("expected valid token to be expired after cleanup time advance")
	}
	assertErrorCode(t, err, ErrCodeInvalidSession)
}

func newTestService(t *testing.T, cfg Config, now time.Time) *service {
	t.Helper()
	svc := NewService(cfg)
	impl, ok := svc.(*service)
	if !ok {
		t.Fatalf("unexpected service type: %T", svc)
	}
	impl.nowFn = func() time.Time { return now }
	return impl
}

func assertErrorCode(t *testing.T, err error, code string) {
	t.Helper()
	var e *common.Error
	if !errors.As(err, &e) {
		t.Fatalf("expected *common.Error, got %T (%v)", err, err)
	}
	if e.Code != code {
		t.Fatalf("unexpected error code: got %s want %s", e.Code, code)
	}
}

func TestServiceValidateCLISession_ConfigValidation(t *testing.T) {
	t.Parallel()

	svc := NewService(Config{DataDir: "", SessionTTL: 0})
	err := svc.ValidateCLISession("personal")
	if err == nil {
		t.Fatal("expected config validation error")
	}
	assertErrorCode(t, err, ErrCodeInvalidArgument)
}

func TestServiceRevokeHTTPSessionMissingIsIdempotent(t *testing.T) {
	t.Parallel()

	svc := newTestService(t, Config{DataDir: t.TempDir(), SessionTTL: 5 * time.Minute}, time.Now().UTC())
	repoHash, err := hashRepoName("personal")
	if err != nil {
		t.Fatalf("hashRepoName failed: %v", err)
	}
	path, err := httpSessionPath(svc.cfg.DataDir, repoHash, "sess_missing")
	if err != nil {
		t.Fatalf("httpSessionPath failed: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	if err := svc.RevokeHTTPSession("personal", "sess_missing", "st_token"); err != nil {
		t.Fatalf("expected idempotent success for missing session, got %v", err)
	}
}

func TestServiceCreateHTTPSessionPurgesExpiredRecords(t *testing.T) {
	t.Parallel()

	base := time.Now().UTC().Truncate(time.Second)
	svc := newTestService(t, Config{DataDir: t.TempDir(), SessionTTL: 5 * time.Minute}, base)

	old, err := svc.CreateHTTPSession("personal")
	if err != nil {
		t.Fatalf("CreateHTTPSession failed: %v", err)
	}

	repoHash, err := hashRepoName("personal")
	if err != nil {
		t.Fatalf("hashRepoName failed: %v", err)
	}
	oldPath, err := httpSessionPath(svc.cfg.DataDir, repoHash, old.SessionID)
	if err != nil {
		t.Fatalf("httpSessionPath failed: %v", err)
	}

	svc.nowFn = func() time.Time { return base.Add(6 * time.Minute) }
	if _, err := svc.CreateHTTPSession("personal"); err != nil {
		t.Fatalf("CreateHTTPSession (after expiry) failed: %v", err)
	}

	if _, err := os.Stat(oldPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected expired session artifact to be purged on create, stat err=%v", err)
	}
}

func TestServiceRevokeCLISessionPurgesExpiredHTTPSiblings(t *testing.T) {
	t.Parallel()

	base := time.Now().UTC().Truncate(time.Second)
	svc := newTestService(t, Config{DataDir: t.TempDir(), SessionTTL: 5 * time.Minute}, base)

	expired, err := svc.CreateHTTPSession("personal")
	if err != nil {
		t.Fatalf("CreateHTTPSession failed: %v", err)
	}

	repoHash, err := hashRepoName("personal")
	if err != nil {
		t.Fatalf("hashRepoName failed: %v", err)
	}
	expiredPath, err := httpSessionPath(svc.cfg.DataDir, repoHash, expired.SessionID)
	if err != nil {
		t.Fatalf("httpSessionPath failed: %v", err)
	}

	svc.nowFn = func() time.Time { return base.Add(6 * time.Minute) }
	if err := svc.RevokeCLISession("personal"); err != nil {
		t.Fatalf("RevokeCLISession failed: %v", err)
	}

	if _, err := os.Stat(expiredPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected expired HTTP artifact to be purged on lock/revoke, stat err=%v", err)
	}
}
