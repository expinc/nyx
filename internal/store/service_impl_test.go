package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"nyx/internal/common"
)

func TestServiceSaveLoadRoundTrip(t *testing.T) {
	svc := NewService()
	repoPath := filepath.Join(t.TempDir(), "repo.json")
	expected := sampleRepo()

	if err := svc.Save(repoPath, expected); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	actual, err := svc.Load(repoPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if actual.Format != expected.Format || actual.Version != expected.Version {
		t.Fatal("loaded top-level repository fields mismatch")
	}
	if !bytes.Equal(actual.KDF.Salt, expected.KDF.Salt) {
		t.Fatal("loaded kdf salt mismatch")
	}
	if !bytes.Equal(actual.KeyWrap.Nonce, expected.KeyWrap.Nonce) {
		t.Fatal("loaded keyWrap nonce mismatch")
	}
	if !bytes.Equal(actual.Payload.Ciphertext, expected.Payload.Ciphertext) {
		t.Fatal("loaded payload ciphertext mismatch")
	}
}

func TestServiceExists(t *testing.T) {
	svc := NewService()
	tmpDir := t.TempDir()
	repoPath := filepath.Join(tmpDir, "repo.json")

	exists, err := svc.Exists(repoPath)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if exists {
		t.Fatal("repository should not exist before save")
	}

	if err := svc.Save(repoPath, sampleRepo()); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	exists, err = svc.Exists(repoPath)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if !exists {
		t.Fatal("repository should exist after save")
	}
}

func TestServiceLoadNotFound(t *testing.T) {
	svc := NewService()
	_, err := svc.Load(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil {
		t.Fatal("expected not-found error")
	}

	e, ok := err.(*common.Error)
	if !ok {
		t.Fatalf("expected *common.Error, got %T", err)
	}
	if e.Code != ErrCodeNotFound {
		t.Fatalf("unexpected error code: %s", e.Code)
	}
}

func TestServiceSaveReplacesExistingFile(t *testing.T) {
	svc := NewService()
	repoPath := filepath.Join(t.TempDir(), "repo.json")

	if err := os.WriteFile(repoPath, []byte("not-json"), 0o600); err != nil {
		t.Fatalf("failed to seed existing file: %v", err)
	}

	if err := svc.Save(repoPath, sampleRepo()); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if _, err := svc.Load(repoPath); err != nil {
		t.Fatalf("Load failed after replacing file: %v", err)
	}
}
