package store

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

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

func sampleRepo() repoenc.Repository {
	return repoenc.Repository{
		Format:  repoenc.FormatNyxRepo,
		Version: 1,
		KDF: repoenc.KDF{
			Algorithm:   repoenc.KDFAlgorithmArgon2id,
			MemoryKiB:   65536,
			Iterations:  3,
			Parallelism: 1,
			Salt:        bytes.Repeat([]byte{0x11}, 16),
		},
		KeyWrap: repoenc.AEAD{
			Algorithm:  repoenc.AEADAlgorithmXChaCha20P,
			Nonce:      bytes.Repeat([]byte{0x22}, 24),
			Ciphertext: []byte{0x01, 0x02, 0x03, 0x04},
		},
		Payload: repoenc.AEAD{
			Algorithm:  repoenc.AEADAlgorithmXChaCha20P,
			Nonce:      bytes.Repeat([]byte{0x33}, 24),
			Ciphertext: []byte{0x05, 0x06, 0x07, 0x08},
		},
	}
}
