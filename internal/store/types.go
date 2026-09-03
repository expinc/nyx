package store

// repositoryEnvelope mirrors the on-disk JSON format with base64-encoded fields.
type repositoryEnvelope struct {
	Format  string          `json:"format"`
	Version int             `json:"version"`
	KDF     kdfEnvelope     `json:"kdf"`
	KeyWrap aeadEnvelope    `json:"keyWrap"`
	Payload payloadEnvelope `json:"payload"`
}

type kdfEnvelope struct {
	Algorithm   string `json:"algorithm"`
	MemoryKiB   uint32 `json:"memoryKiB"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	SaltB64     string `json:"saltB64"`
}

type aeadEnvelope struct {
	Algorithm     string `json:"algorithm"`
	NonceB64      string `json:"nonceB64"`
	CiphertextB64 string `json:"ciphertextB64"`
}

type payloadEnvelope struct {
	Algorithm     string `json:"algorithm"`
	NonceB64      string `json:"nonceB64"`
	CiphertextB64 string `json:"ciphertextB64"`
}
