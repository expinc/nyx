package store

import (
	"bytes"

	"nyx/internal/common/cryptoprofile"
	"nyx/internal/model/repoenc"
)

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
			Ciphertext: bytes.Repeat([]byte{0x44}, cryptoprofile.DEKSizeBytes+cryptoprofile.AEADTagSizeBytes),
		},
		Payload: repoenc.AEAD{
			Algorithm:  repoenc.AEADAlgorithmXChaCha20P,
			Nonce:      bytes.Repeat([]byte{0x33}, 24),
			Ciphertext: bytes.Repeat([]byte{0x55}, cryptoprofile.AEADTagSizeBytes*2),
		},
	}
}
