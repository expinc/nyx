package store

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestRenderParseRepositoryJSONRoundTrip(t *testing.T) {
	repo := sampleRepo()

	b, err := RenderRepositoryJSON(repo)
	if err != nil {
		t.Fatalf("RenderRepositoryJSON failed: %v", err)
	}

	decoded, err := ParseRepositoryJSON(b)
	if err != nil {
		t.Fatalf("ParseRepositoryJSON failed: %v", err)
	}

	if decoded.Format != repo.Format || decoded.Version != repo.Version {
		t.Fatal("top-level fields mismatch")
	}
	if !bytes.Equal(decoded.KDF.Salt, repo.KDF.Salt) {
		t.Fatal("kdf salt mismatch")
	}
	if !bytes.Equal(decoded.KeyWrap.Nonce, repo.KeyWrap.Nonce) {
		t.Fatal("keyWrap nonce mismatch")
	}
	if !bytes.Equal(decoded.KeyWrap.Ciphertext, repo.KeyWrap.Ciphertext) {
		t.Fatal("keyWrap ciphertext mismatch")
	}
	if !bytes.Equal(decoded.Payload.Nonce, repo.Payload.Nonce) {
		t.Fatal("payload nonce mismatch")
	}
	if !bytes.Equal(decoded.Payload.Ciphertext, repo.Payload.Ciphertext) {
		t.Fatal("payload ciphertext mismatch")
	}
}

func TestParseRepositoryJSONRejectsBadBase64(t *testing.T) {
	input := []byte(`{"format":"nyx-repo","version":1,"kdf":{"algorithm":"argon2id","memoryKiB":65536,"iterations":3,"parallelism":1,"saltB64":"!!!"},"keyWrap":{"algorithm":"xchacha20poly1305","nonceB64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ciphertextB64":"AQID"},"payload":{"algorithm":"xchacha20poly1305","nonceB64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ciphertextB64":"AQID"}}`)
	_, err := ParseRepositoryJSON(input)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseRepositoryJSONRejectsInvalidNonceSize(t *testing.T) {
	repo := sampleRepo()
	env, err := repositoryToEnvelope(repo)
	if err != nil {
		t.Fatalf("repositoryToEnvelope failed: %v", err)
	}
	env.KeyWrap.NonceB64 = base64.StdEncoding.EncodeToString([]byte{1, 2, 3})

	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	_, err = ParseRepositoryJSON(b)
	if err == nil {
		t.Fatal("expected nonce-size error")
	}
}

func TestParseRepositoryJSONRejectsUnsupportedAlgorithms(t *testing.T) {
	repo := sampleRepo()
	env, err := repositoryToEnvelope(repo)
	if err != nil {
		t.Fatalf("repositoryToEnvelope failed: %v", err)
	}

	env.KeyWrap.Algorithm = "aes-gcm"
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	_, err = ParseRepositoryJSON(b)
	if err == nil {
		t.Fatal("expected unsupported algorithm error")
	}
}

func TestParseRepositoryJSONRejectsUnsupportedVersion(t *testing.T) {
	repo := sampleRepo()
	env, err := repositoryToEnvelope(repo)
	if err != nil {
		t.Fatalf("repositoryToEnvelope failed: %v", err)
	}

	env.Version = 2
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	_, err = ParseRepositoryJSON(b)
	if err == nil {
		t.Fatal("expected unsupported version error")
	}
}

func TestParseRepositoryJSONRejectsMissingRequiredField(t *testing.T) {
	repo := sampleRepo()
	env, err := repositoryToEnvelope(repo)
	if err != nil {
		t.Fatalf("repositoryToEnvelope failed: %v", err)
	}

	env.KDF.SaltB64 = ""
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	_, err = ParseRepositoryJSON(b)
	if err == nil {
		t.Fatal("expected missing required field error")
	}
	if !strings.Contains(err.Error(), "kdf.saltB64 is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseRepositoryJSONRejectsInvalidKeyWrapCiphertextLength(t *testing.T) {
	repo := sampleRepo()
	env, err := repositoryToEnvelope(repo)
	if err != nil {
		t.Fatalf("repositoryToEnvelope failed: %v", err)
	}

	env.KeyWrap.CiphertextB64 = base64.StdEncoding.EncodeToString([]byte{1, 2, 3})
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	_, err = ParseRepositoryJSON(b)
	if err == nil {
		t.Fatal("expected keyWrap ciphertext length error")
	}
}

func TestParseRepositoryJSONRejectsTooShortPayloadCiphertext(t *testing.T) {
	repo := sampleRepo()
	env, err := repositoryToEnvelope(repo)
	if err != nil {
		t.Fatalf("repositoryToEnvelope failed: %v", err)
	}

	env.Payload.CiphertextB64 = base64.StdEncoding.EncodeToString([]byte{1, 2, 3})
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	_, err = ParseRepositoryJSON(b)
	if err == nil {
		t.Fatal("expected payload ciphertext length error")
	}
}

func TestBuildAADDeterministicAndDistinct(t *testing.T) {
	repo := sampleRepo()

	keyWrapAAD1, err := BuildKeyWrapAAD(repo)
	if err != nil {
		t.Fatalf("BuildKeyWrapAAD failed: %v", err)
	}
	keyWrapAAD2, err := BuildKeyWrapAAD(repo)
	if err != nil {
		t.Fatalf("BuildKeyWrapAAD failed: %v", err)
	}
	if !bytes.Equal(keyWrapAAD1, keyWrapAAD2) {
		t.Fatal("keyWrap AAD is not deterministic")
	}

	payloadAAD1, err := BuildPayloadAAD(repo)
	if err != nil {
		t.Fatalf("BuildPayloadAAD failed: %v", err)
	}
	payloadAAD2, err := BuildPayloadAAD(repo)
	if err != nil {
		t.Fatalf("BuildPayloadAAD failed: %v", err)
	}
	if !bytes.Equal(payloadAAD1, payloadAAD2) {
		t.Fatal("payload AAD is not deterministic")
	}

	if bytes.Equal(keyWrapAAD1, payloadAAD1) {
		t.Fatal("keyWrap and payload AAD must differ")
	}
}
