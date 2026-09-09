package store

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"nyx/internal/common/cryptoprofile"
	"nyx/internal/model/repoenc"
)

const (
	supportedRepoVersion = 1
)

// ParseRepositoryJSON parses repository JSON and returns the raw-byte encrypted model.
func ParseRepositoryJSON(data []byte) (repoenc.Repository, error) {
	var env repositoryEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return repoenc.Repository{}, NewInvalidFormatError("invalid repository json", err)
	}
	return envelopeToRepository(env)
}

// RenderRepositoryJSON renders the raw-byte encrypted model to repository JSON.
func RenderRepositoryJSON(repo repoenc.Repository) ([]byte, error) {
	env, err := repositoryToEnvelope(repo)
	if err != nil {
		return nil, err
	}
	bytes, err := json.Marshal(env)
	if err != nil {
		return nil, NewInvalidFormatError("failed to marshal repository json", err)
	}
	return bytes, nil
}

// BuildKeyWrapAAD builds canonical AAD JSON bytes for key-wrap AEAD.
func BuildKeyWrapAAD(repo repoenc.Repository) ([]byte, error) {
	env, err := repositoryToEnvelope(repo)
	if err != nil {
		return nil, err
	}
	return marshalAAD(keyWrapAADEnvelope{
		Format:  env.Format,
		Version: env.Version,
		KDF:     env.KDF,
		KeyWrap: algorithmEnvelope{Algorithm: env.KeyWrap.Algorithm},
	}, "failed to marshal keyWrap aad")
}

// BuildPayloadAAD builds canonical AAD JSON bytes for payload AEAD.
func BuildPayloadAAD(repo repoenc.Repository) ([]byte, error) {
	env, err := repositoryToEnvelope(repo)
	if err != nil {
		return nil, err
	}
	return marshalAAD(payloadAADEnvelope{
		Format:  env.Format,
		Version: env.Version,
		KDF:     env.KDF,
		Payload: algorithmEnvelope{Algorithm: env.Payload.Algorithm},
	}, "failed to marshal payload aad")
}

func marshalAAD(v any, message string) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, NewInvalidFormatError(message, err)
	}
	return b, nil
}

func repositoryToEnvelope(repo repoenc.Repository) (repositoryEnvelope, error) {
	if err := repo.Validate(); err != nil {
		return repositoryEnvelope{}, NewInvalidFormatError("invalid repository model", err)
	}

	saltB64 := base64.StdEncoding.EncodeToString(repo.KDF.Salt)
	nonceWrapB64 := base64.StdEncoding.EncodeToString(repo.KeyWrap.Nonce)
	ctWrapB64 := base64.StdEncoding.EncodeToString(repo.KeyWrap.Ciphertext)
	noncePayloadB64 := base64.StdEncoding.EncodeToString(repo.Payload.Nonce)
	ctPayloadB64 := base64.StdEncoding.EncodeToString(repo.Payload.Ciphertext)

	return repositoryEnvelope{
		Format:  repo.Format,
		Version: repo.Version,
		KDF: kdfEnvelope{
			Algorithm:   repo.KDF.Algorithm,
			MemoryKiB:   repo.KDF.MemoryKiB,
			Iterations:  repo.KDF.Iterations,
			Parallelism: repo.KDF.Parallelism,
			SaltB64:     saltB64,
		},
		KeyWrap: aeadEnvelope{
			Algorithm:     repo.KeyWrap.Algorithm,
			NonceB64:      nonceWrapB64,
			CiphertextB64: ctWrapB64,
		},
		Payload: payloadEnvelope{
			Algorithm:     repo.Payload.Algorithm,
			NonceB64:      noncePayloadB64,
			CiphertextB64: ctPayloadB64,
		},
	}, nil
}

func envelopeToRepository(env repositoryEnvelope) (repoenc.Repository, error) {
	if err := validateEnvelopeStructure(env); err != nil {
		return repoenc.Repository{}, err
	}

	salt, err := decodeB64Field(env.KDF.SaltB64)
	if err != nil {
		return repoenc.Repository{}, NewInvalidFormatError("invalid base64 in kdf.saltB64", err)
	}
	if len(salt) < cryptoprofile.MinSaltBytes {
		return repoenc.Repository{}, NewInvalidFormatError(fmt.Sprintf("kdf.saltB64 must decode to at least %d bytes", cryptoprofile.MinSaltBytes), nil)
	}

	wrapNonce, err := decodeB64Field(env.KeyWrap.NonceB64)
	if err != nil {
		return repoenc.Repository{}, NewInvalidFormatError("invalid base64 in keyWrap.nonceB64", err)
	}
	if len(wrapNonce) != cryptoprofile.XChaCha20NonceBytes {
		return repoenc.Repository{}, NewInvalidFormatError(fmt.Sprintf("keyWrap.nonceB64 must decode to %d bytes", cryptoprofile.XChaCha20NonceBytes), nil)
	}

	wrapCiphertext, err := decodeB64Field(env.KeyWrap.CiphertextB64)
	if err != nil {
		return repoenc.Repository{}, NewInvalidFormatError("invalid base64 in keyWrap.ciphertextB64", err)
	}
	if len(wrapCiphertext) != cryptoprofile.DEKSizeBytes+cryptoprofile.AEADTagSizeBytes {
		return repoenc.Repository{}, NewInvalidFormatError(
			fmt.Sprintf("keyWrap.ciphertextB64 must decode to %d bytes", cryptoprofile.DEKSizeBytes+cryptoprofile.AEADTagSizeBytes),
			nil,
		)
	}

	payloadNonce, err := decodeB64Field(env.Payload.NonceB64)
	if err != nil {
		return repoenc.Repository{}, NewInvalidFormatError("invalid base64 in payload.nonceB64", err)
	}
	if len(payloadNonce) != cryptoprofile.XChaCha20NonceBytes {
		return repoenc.Repository{}, NewInvalidFormatError(fmt.Sprintf("payload.nonceB64 must decode to %d bytes", cryptoprofile.XChaCha20NonceBytes), nil)
	}

	payloadCiphertext, err := decodeB64Field(env.Payload.CiphertextB64)
	if err != nil {
		return repoenc.Repository{}, NewInvalidFormatError("invalid base64 in payload.ciphertextB64", err)
	}
	if len(payloadCiphertext) < cryptoprofile.AEADTagSizeBytes {
		return repoenc.Repository{}, NewInvalidFormatError(
			fmt.Sprintf("payload.ciphertextB64 must decode to at least %d bytes", cryptoprofile.AEADTagSizeBytes),
			nil,
		)
	}

	repo := repoenc.Repository{
		Format:  env.Format,
		Version: env.Version,
		KDF: repoenc.KDF{
			Algorithm:   env.KDF.Algorithm,
			MemoryKiB:   env.KDF.MemoryKiB,
			Iterations:  env.KDF.Iterations,
			Parallelism: env.KDF.Parallelism,
			Salt:        salt,
		},
		KeyWrap: repoenc.AEAD{
			Algorithm:  env.KeyWrap.Algorithm,
			Nonce:      wrapNonce,
			Ciphertext: wrapCiphertext,
		},
		Payload: repoenc.AEAD{
			Algorithm:  env.Payload.Algorithm,
			Nonce:      payloadNonce,
			Ciphertext: payloadCiphertext,
		},
	}

	if err := repo.Validate(); err != nil {
		return repoenc.Repository{}, NewInvalidFormatError("invalid repository model", err)
	}
	return repo, nil
}

func decodeB64Field(raw string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	if len(decoded) == 0 {
		return nil, fmt.Errorf("decoded bytes must not be empty")
	}
	return decoded, nil
}

func validateEnvelopeStructure(env repositoryEnvelope) error {
	if env.Format != repoenc.FormatNyxRepo {
		return NewInvalidFormatError("format must be nyx-repo", nil)
	}
	if env.Version != supportedRepoVersion {
		return NewInvalidFormatError("unsupported repository version", nil)
	}

	if env.KDF.Algorithm != repoenc.KDFAlgorithmArgon2id {
		return NewInvalidFormatError("kdf.algorithm must be argon2id", nil)
	}
	if env.KeyWrap.Algorithm != repoenc.AEADAlgorithmXChaCha20P {
		return NewInvalidFormatError("keyWrap.algorithm must be xchacha20poly1305", nil)
	}
	if env.Payload.Algorithm != repoenc.AEADAlgorithmXChaCha20P {
		return NewInvalidFormatError("payload.algorithm must be xchacha20poly1305", nil)
	}

	if env.KDF.SaltB64 == "" {
		return NewInvalidFormatError("kdf.saltB64 is required", nil)
	}
	if env.KeyWrap.NonceB64 == "" {
		return NewInvalidFormatError("keyWrap.nonceB64 is required", nil)
	}
	if env.KeyWrap.CiphertextB64 == "" {
		return NewInvalidFormatError("keyWrap.ciphertextB64 is required", nil)
	}
	if env.Payload.NonceB64 == "" {
		return NewInvalidFormatError("payload.nonceB64 is required", nil)
	}
	if env.Payload.CiphertextB64 == "" {
		return NewInvalidFormatError("payload.ciphertextB64 is required", nil)
	}

	if (env.KeyWrap.NonceB64 == "") != (env.KeyWrap.CiphertextB64 == "") {
		return NewInvalidFormatError("keyWrap nonce/ciphertext must be present together", nil)
	}
	if (env.Payload.NonceB64 == "") != (env.Payload.CiphertextB64 == "") {
		return NewInvalidFormatError("payload nonce/ciphertext must be present together", nil)
	}

	return nil
}
