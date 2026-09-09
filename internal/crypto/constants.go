package crypto

import "nyx/internal/common/cryptoprofile"

const (
	AlgorithmArgon2id          = cryptoprofile.AlgorithmArgon2id
	AlgorithmXChaCha20Poly1305 = cryptoprofile.AlgorithmXChaCha20Poly1305
)

const (
	DefaultKDFMemoryKiB   uint32 = 65536
	DefaultKDFIterations  uint32 = 3
	DefaultKDFOutputLen   uint32 = 32
	DefaultKDFParallelism uint8  = 1
)

const (
	DEKSizeBytes        = cryptoprofile.DEKSizeBytes
	XChaCha20NonceBytes = cryptoprofile.XChaCha20NonceBytes
	MinSaltBytes        = cryptoprofile.MinSaltBytes
	DefaultSaltBytes    = cryptoprofile.MinSaltBytes
)
