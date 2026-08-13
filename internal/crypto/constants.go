package crypto

const (
	AlgorithmArgon2id          = "argon2id"
	AlgorithmXChaCha20Poly1305 = "xchacha20poly1305"
)

const (
	DefaultKDFMemoryKiB   uint32 = 65536
	DefaultKDFIterations  uint32 = 3
	DefaultKDFOutputLen   uint32 = 32
	DefaultKDFParallelism uint8  = 1
)

const (
	DEKSizeBytes        = 32
	XChaCha20NonceBytes = 24
	MinSaltBytes        = 16
)
