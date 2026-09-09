package cryptoprofile

const (
	DEKSizeBytes        = 32
	XChaCha20NonceBytes = 24
	MinSaltBytes        = 16
	AEADTagSizeBytes    = 16
)

const (
	AlgorithmArgon2id          = "argon2id"
	AlgorithmXChaCha20Poly1305 = "xchacha20poly1305"
)
