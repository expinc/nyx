package crypto

// KDFParams defines password-based key derivation inputs.
type KDFParams struct {
	Name        string
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	OutputLen   uint32
	Salt        []byte
}

// AEADEncryptInput is used for XChaCha20-Poly1305 encryption operations.
type AEADEncryptInput struct {
	Algorithm string
	Key       []byte
	Nonce     []byte
	Plaintext []byte
	AAD       []byte
}

// AEADDecryptInput is used for XChaCha20-Poly1305 decryption operations.
type AEADDecryptInput struct {
	Algorithm  string
	Key        []byte
	Nonce      []byte
	Ciphertext []byte
	AAD        []byte
}
