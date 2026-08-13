package crypto

// Service defines cryptographic operations used by core/store flows.
type Service interface {
	RandomBytes(size int) ([]byte, error)
	GenerateDEK() ([]byte, error)
	GenerateNonce() ([]byte, error)

	DeriveKEK(password []byte, params KDFParams) ([]byte, error)

	Encrypt(in AEADEncryptInput) ([]byte, error)
	Decrypt(in AEADDecryptInput) ([]byte, error)
}
