package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

type service struct{}

func (s *service) RandomBytes(size int) ([]byte, error) {
	if size <= 0 {
		return nil, NewInvalidParameterError("size must be > 0", nil)
	}

	out := make([]byte, size)
	if _, err := rand.Read(out); err != nil {
		return nil, NewInternalError("failed to read cryptographic random bytes", err)
	}
	return out, nil
}

func (s *service) GenerateSalt() ([]byte, error) {
	return s.RandomBytes(MinSaltBytes)
}

func (s *service) GenerateDEK() ([]byte, error) {
	return s.RandomBytes(DEKSizeBytes)
}

func (s *service) GenerateNonce() ([]byte, error) {
	return s.RandomBytes(XChaCha20NonceBytes)
}

func (s *service) DeriveKEK(password []byte, params KDFParams) ([]byte, error) {
	if params.Algorithm != AlgorithmArgon2id {
		return nil, NewInvalidParameterError(
			fmt.Sprintf("unsupported kdf algorithm: %q", params.Algorithm),
			nil,
		)
	}
	if len(password) == 0 {
		return nil, NewInvalidParameterError("password must not be empty", nil)
	}
	if params.MemoryKiB == 0 {
		return nil, NewInvalidParameterError("memoryKiB must be > 0", nil)
	}
	if params.Iterations == 0 {
		return nil, NewInvalidParameterError("iterations must be > 0", nil)
	}
	if params.Parallelism == 0 {
		return nil, NewInvalidParameterError("parallelism must be > 0", nil)
	}
	if params.OutputLen == 0 {
		return nil, NewInvalidParameterError("outputLength must be > 0", nil)
	}
	if len(params.Salt) < MinSaltBytes {
		return nil, NewInvalidParameterError("salt length is below minimum", nil)
	}

	kek := argon2.IDKey(
		password,
		params.Salt,
		params.Iterations,
		params.MemoryKiB,
		params.Parallelism,
		params.OutputLen,
	)
	return kek, nil
}

func (s *service) Encrypt(in AEADEncryptInput) ([]byte, error) {
	if err := validateAEADEncryptInput(in); err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(in.Key)
	if err != nil {
		return nil, NewInternalError("failed to initialize XChaCha20-Poly1305", err)
	}

	ciphertext := aead.Seal(nil, in.Nonce, in.Plaintext, in.AAD)
	return ciphertext, nil
}

func (s *service) Decrypt(in AEADDecryptInput) ([]byte, error) {
	if err := validateAEADDecryptInput(in); err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(in.Key)
	if err != nil {
		return nil, NewInternalError("failed to initialize XChaCha20-Poly1305", err)
	}

	plaintext, err := aead.Open(nil, in.Nonce, in.Ciphertext, in.AAD)
	if err != nil {
		// Return a generic auth failure to avoid leaking decryption internals.
		return nil, NewAuthFailedError("authentication failed", nil)
	}
	return plaintext, nil
}

func validateAEADEncryptInput(in AEADEncryptInput) error {
	if in.Algorithm != AlgorithmXChaCha20Poly1305 {
		return NewInvalidParameterError(
			fmt.Sprintf("unsupported algorithm: %s", in.Algorithm),
			nil,
		)
	}
	if len(in.Key) != chacha20poly1305.KeySize {
		return NewInvalidParameterError(
			fmt.Sprintf("key length must be %d bytes", chacha20poly1305.KeySize),
			nil,
		)
	}
	if len(in.Nonce) != chacha20poly1305.NonceSizeX {
		return NewInvalidParameterError(
			fmt.Sprintf("nonce length must be %d bytes", chacha20poly1305.NonceSizeX),
			nil,
		)
	}
	return nil
}

func validateAEADDecryptInput(in AEADDecryptInput) error {
	if in.Algorithm != AlgorithmXChaCha20Poly1305 {
		return NewInvalidParameterError(
			fmt.Sprintf("unsupported aead algorithm: %s", in.Algorithm),
			nil,
		)
	}
	if len(in.Key) != chacha20poly1305.KeySize {
		return NewInvalidParameterError(
			fmt.Sprintf("key length must be %d bytes", chacha20poly1305.KeySize),
			nil,
		)
	}
	if len(in.Nonce) != chacha20poly1305.NonceSizeX {
		return NewInvalidParameterError(
			fmt.Sprintf("nonce length must be %d bytes", chacha20poly1305.NonceSizeX),
			nil,
		)
	}
	return nil
}
