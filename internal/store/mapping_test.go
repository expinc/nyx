package store

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"nyx/internal/common"
	"nyx/internal/common/cryptoprofile"
	"nyx/internal/model/repoenc"
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
	assertStoreErrorCode(t, err, ErrCodeInvalidFormat)
}

func TestParseRepositoryJSONRejectsMalformedJSON(t *testing.T) {
	_, err := ParseRepositoryJSON([]byte(`{"format":"nyx-repo",`))
	if err == nil {
		t.Fatal("expected malformed json error")
	}
	assertStoreErrorCode(t, err, ErrCodeInvalidFormat)
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
	assertStoreErrorCode(t, err, ErrCodeInvalidFormat)
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
	assertStoreErrorCode(t, err, ErrCodeInvalidFormat)
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
	assertStoreErrorCode(t, err, ErrCodeInvalidFormat)
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
	assertStoreErrorCode(t, err, ErrCodeInvalidFormat)
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
	assertStoreErrorCode(t, err, ErrCodeInvalidFormat)
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
	assertStoreErrorCode(t, err, ErrCodeInvalidFormat)
}

func TestRenderRepositoryJSONMatchesSpecFieldNamesAndLabels(t *testing.T) {
	b, err := RenderRepositoryJSON(sampleRepo())
	if err != nil {
		t.Fatalf("RenderRepositoryJSON failed: %v", err)
	}

	var root map[string]json.RawMessage
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatalf("json.Unmarshal root failed: %v", err)
	}

	requiredRoot := []string{"format", "version", "kdf", "keyWrap", "payload"}
	for _, k := range requiredRoot {
		if _, ok := root[k]; !ok {
			t.Fatalf("missing root field: %s", k)
		}
	}

	var kdf map[string]json.RawMessage
	if err := json.Unmarshal(root["kdf"], &kdf); err != nil {
		t.Fatalf("json.Unmarshal kdf failed: %v", err)
	}
	requiredKDF := []string{"algorithm", "memoryKiB", "iterations", "parallelism", "saltB64"}
	for _, k := range requiredKDF {
		if _, ok := kdf[k]; !ok {
			t.Fatalf("missing kdf field: %s", k)
		}
	}

	var keyWrap map[string]json.RawMessage
	if err := json.Unmarshal(root["keyWrap"], &keyWrap); err != nil {
		t.Fatalf("json.Unmarshal keyWrap failed: %v", err)
	}
	requiredAEAD := []string{"algorithm", "nonceB64", "ciphertextB64"}
	for _, k := range requiredAEAD {
		if _, ok := keyWrap[k]; !ok {
			t.Fatalf("missing keyWrap field: %s", k)
		}
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(root["payload"], &payload); err != nil {
		t.Fatalf("json.Unmarshal payload failed: %v", err)
	}
	for _, k := range requiredAEAD {
		if _, ok := payload[k]; !ok {
			t.Fatalf("missing payload field: %s", k)
		}
	}

	var rendered repoenc.Repository
	rendered, err = ParseRepositoryJSON(b)
	if err != nil {
		t.Fatalf("ParseRepositoryJSON failed: %v", err)
	}
	if rendered.KDF.Algorithm != cryptoprofile.AlgorithmArgon2id {
		t.Fatalf("unexpected kdf algorithm: %s", rendered.KDF.Algorithm)
	}
	if rendered.KeyWrap.Algorithm != cryptoprofile.AlgorithmXChaCha20Poly1305 {
		t.Fatalf("unexpected keyWrap algorithm: %s", rendered.KeyWrap.Algorithm)
	}
	if rendered.Payload.Algorithm != cryptoprofile.AlgorithmXChaCha20Poly1305 {
		t.Fatalf("unexpected payload algorithm: %s", rendered.Payload.Algorithm)
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

func assertStoreErrorCode(t *testing.T, err error, expected string) {
	t.Helper()
	e, ok := err.(*common.Error)
	if !ok {
		t.Fatalf("expected *common.Error, got %T", err)
	}
	if e.Code != expected {
		t.Fatalf("unexpected error code: got %s want %s", e.Code, expected)
	}
}
