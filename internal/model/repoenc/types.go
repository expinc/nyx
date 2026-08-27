package repoenc

import "fmt"

const (
	FormatNyxRepo           = "nyx-repo"
	KDFAlgorithmArgon2id    = "argon2id"
	AEADAlgorithmXChaCha20P = "xchacha20poly1305"
)

// Repository is the encrypted repository container model using raw byte fields.
type Repository struct {
	Format  string
	Version int
	KDF     KDF
	KeyWrap AEAD
	Payload AEAD
}

// KDF stores persisted key-derivation parameters with raw salt bytes.
type KDF struct {
	Algorithm   string
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	Salt        []byte
}

// AEAD stores AEAD metadata with raw nonce and ciphertext bytes.
type AEAD struct {
	Algorithm  string
	Nonce      []byte
	Ciphertext []byte
}

func (r Repository) Validate() error {
	if r.Format == "" {
		return fmt.Errorf("format is required")
	}
	if r.Version <= 0 {
		return fmt.Errorf("version must be positive")
	}
	if err := r.KDF.Validate(); err != nil {
		return fmt.Errorf("invalid kdf: %w", err)
	}
	if err := r.KeyWrap.Validate(); err != nil {
		return fmt.Errorf("invalid keyWrap: %w", err)
	}
	if err := r.Payload.Validate(); err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}
	return nil
}

func (k KDF) Validate() error {
	if k.Algorithm == "" {
		return fmt.Errorf("algorithm is required")
	}
	if k.MemoryKiB == 0 || k.Iterations == 0 || k.Parallelism == 0 {
		return fmt.Errorf("memoryKiB, iterations, and parallelism must be non-zero")
	}
	if len(k.Salt) == 0 {
		return fmt.Errorf("salt is required")
	}
	return nil
}

func (a AEAD) Validate() error {
	if a.Algorithm == "" {
		return fmt.Errorf("algorithm is required")
	}
	if len(a.Nonce) == 0 {
		return fmt.Errorf("nonce is required")
	}
	if len(a.Ciphertext) == 0 {
		return fmt.Errorf("ciphertext is required")
	}
	return nil
}
