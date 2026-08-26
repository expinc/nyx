package crypto

import (
	"bytes"
	"testing"

	"nyx/internal/common"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestDeriveKEK_IsDeterministicForSameInputs(t *testing.T) {
	svc := NewService()

	password := []byte("correct-horse-battery-staple")
	params := KDFParams{
		Algorithm:   AlgorithmArgon2id,
		MemoryKiB:   DefaultKDFMemoryKiB,
		Iterations:  DefaultKDFIterations,
		Parallelism: DefaultKDFParallelism,
		OutputLen:   DefaultKDFOutputLen,
		Salt:        []byte("0123456789abcdef"),
	}

	kek1, err := svc.DeriveKEK(password, params)
	if err != nil {
		t.Fatalf("DeriveKEK returned error on first call: %v", err)
	}

	kek2, err := svc.DeriveKEK(password, params)
	if err != nil {
		t.Fatalf("DeriveKEK returned error on second call: %v", err)
	}

	if !bytes.Equal(kek1, kek2) {
		t.Fatalf("expected deterministic KEK for same inputs")
	}
}

func TestRandomBytes_SizeAndNonTrivialRandomness(t *testing.T) {
	svc := NewService()

	const n = 32
	b1, err := svc.RandomBytes(n)
	if err != nil {
		t.Fatalf("RandomBytes returned error on first call: %v", err)
	}
	if len(b1) != n {
		t.Fatalf("expected RandomBytes length %d, got %d", n, len(b1))
	}

	b2, err := svc.RandomBytes(n)
	if err != nil {
		t.Fatalf("RandomBytes returned error on second call: %v", err)
	}
	if len(b2) != n {
		t.Fatalf("expected RandomBytes length %d, got %d", n, len(b2))
	}

	zero := make([]byte, n)
	if bytes.Equal(b1, zero) {
		t.Fatalf("unexpected all-zero output from RandomBytes")
	}
	if bytes.Equal(b2, zero) {
		t.Fatalf("unexpected all-zero output from RandomBytes")
	}
	if bytes.Equal(b1, b2) {
		t.Fatalf("unexpected identical outputs from consecutive RandomBytes calls")
	}
}

func TestGeneratedSecretMaterialSizes(t *testing.T) {
	svc := NewService()

	salt, err := svc.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt returned error: %v", err)
	}
	if len(salt) != DefaultSaltBytes {
		t.Fatalf("expected salt length %d, got %d", DefaultSaltBytes, len(salt))
	}

	dek, err := svc.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK returned error: %v", err)
	}
	if len(dek) != DEKSizeBytes {
		t.Fatalf("expected DEK length %d, got %d", DEKSizeBytes, len(dek))
	}

	nonce, err := svc.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce returned error: %v", err)
	}
	if len(nonce) != XChaCha20NonceBytes {
		t.Fatalf("expected nonce length %d, got %d", XChaCha20NonceBytes, len(nonce))
	}
}

func TestWrapUnwrapDEK_RoundTrip(t *testing.T) {
	svc := NewService()

	kek, err := svc.DeriveKEK(
		[]byte("master-password"),
		KDFParams{
			Algorithm:   AlgorithmArgon2id,
			MemoryKiB:   DefaultKDFMemoryKiB,
			Iterations:  DefaultKDFIterations,
			Parallelism: DefaultKDFParallelism,
			OutputLen:   DefaultKDFOutputLen,
			Salt:        []byte("0123456789abcdef"),
		},
	)
	if err != nil {
		t.Fatalf("DeriveKEK returned error: %v", err)
	}

	dek, err := svc.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK returned error: %v", err)
	}

	nonce, err := svc.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce returned error: %v", err)
	}

	aad := []byte(`{"kind":"keyWrap"}`)

	wrapped, err := svc.Encrypt(AEADEncryptInput{
		Algorithm: AlgorithmXChaCha20Poly1305,
		Key:       kek,
		Nonce:     nonce,
		Plaintext: dek,
		AAD:       aad,
	})
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	unwrapped, err := svc.Decrypt(AEADDecryptInput{
		Algorithm:  AlgorithmXChaCha20Poly1305,
		Key:        kek,
		Nonce:      nonce,
		Ciphertext: wrapped,
		AAD:        aad,
	})
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}

	if !bytes.Equal(unwrapped, dek) {
		t.Fatalf("unwrapped DEK does not match original DEK")
	}
}

func TestEncryptDecryptPayload_RoundTrip(t *testing.T) {
	svc := NewService()

	key, err := svc.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK returned error: %v", err)
	}

	nonce, err := svc.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce returned error: %v", err)
	}

	plaintext := []byte(`{"schemaVersion":1,"createdAt":"2026-08-25T00:00:00Z","secrets":[{"id":"sec_1","type":"password","title":"GitHub"}]}`)
	aad := []byte(`{"kind":"payload"}`)

	ciphertext, err := svc.Encrypt(AEADEncryptInput{
		Algorithm: AlgorithmXChaCha20Poly1305,
		Key:       key,
		Nonce:     nonce,
		Plaintext: plaintext,
		AAD:       aad,
	})
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	decrypted, err := svc.Decrypt(AEADDecryptInput{
		Algorithm:  AlgorithmXChaCha20Poly1305,
		Key:        key,
		Nonce:      nonce,
		Ciphertext: ciphertext,
		AAD:        aad,
	})
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted payload does not match plaintext")
	}
}

func TestDecrypt_WithWrongKey_Fails(t *testing.T) {
	svc := NewService()

	rightKey, err := svc.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK returned error for right key: %v", err)
	}

	wrongKey, err := svc.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK returned error for wrong key: %v", err)
	}

	if bytes.Equal(rightKey, wrongKey) {
		t.Fatalf("unexpected identical generated keys")
	}

	nonce, err := svc.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce returned error: %v", err)
	}

	aad := []byte(`{"kind":"keyWrap"}`)
	plaintext := []byte("secret-dek-bytes")

	ciphertext, err := svc.Encrypt(AEADEncryptInput{
		Algorithm: AlgorithmXChaCha20Poly1305,
		Key:       rightKey,
		Nonce:     nonce,
		Plaintext: plaintext,
		AAD:       aad,
	})
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	_, err = svc.Decrypt(AEADDecryptInput{
		Algorithm:  AlgorithmXChaCha20Poly1305,
		Key:        wrongKey,
		Nonce:      nonce,
		Ciphertext: ciphertext,
		AAD:        aad,
	})
	if err == nil {
		t.Fatalf("expected decrypt error with wrong key")
	}

	cryptoErr, ok := err.(*common.Error)
	if !ok {
		t.Fatalf("expected *common.Error, got %T", err)
	}
	if cryptoErr.Code != ErrCodeAuthFailed {
		t.Fatalf("expected error code %q, got %q", ErrCodeAuthFailed, cryptoErr.Code)
	}
}

func TestDecrypt_WithWrongAAD_Fails(t *testing.T) {
	svc := NewService()

	key, err := svc.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK returned error: %v", err)
	}

	nonce, err := svc.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce returned error: %v", err)
	}

	plaintext := []byte("payload-data")
	rightAAD := []byte(`{"kind":"payload"}`)
	wrongAAD := []byte(`{"kind":"payload-tampered"}`)

	ciphertext, err := svc.Encrypt(AEADEncryptInput{
		Algorithm: AlgorithmXChaCha20Poly1305,
		Key:       key,
		Nonce:     nonce,
		Plaintext: plaintext,
		AAD:       rightAAD,
	})
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	_, err = svc.Decrypt(AEADDecryptInput{
		Algorithm:  AlgorithmXChaCha20Poly1305,
		Key:        key,
		Nonce:      nonce,
		Ciphertext: ciphertext,
		AAD:        wrongAAD,
	})
	if err == nil {
		t.Fatalf("expected decrypt error with wrong AAD")
	}

	cryptoErr, ok := err.(*common.Error)
	if !ok {
		t.Fatalf("expected *common.Error, got %T", err)
	}
	if cryptoErr.Code != ErrCodeAuthFailed {
		t.Fatalf("expected error code %q, got %q", ErrCodeAuthFailed, cryptoErr.Code)
	}
}

func TestEncrypt_InvalidKeyLength_Fails(t *testing.T) {
	svc := NewService()

	nonce, err := svc.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce returned error: %v", err)
	}

	_, err = svc.Encrypt(AEADEncryptInput{
		Algorithm: AlgorithmXChaCha20Poly1305,
		Key:       make([]byte, chacha20poly1305.KeySize-1),
		Nonce:     nonce,
		Plaintext: []byte("payload"),
		AAD:       []byte(`{"kind":"payload"}`),
	})
	if err == nil {
		t.Fatalf("expected encrypt error with invalid key length")
	}

	cryptoErr, ok := err.(*common.Error)
	if !ok {
		t.Fatalf("expected *common.Error, got %T", err)
	}
	if cryptoErr.Code != ErrCodeInvalidParameter {
		t.Fatalf("expected error code %q, got %q", ErrCodeInvalidParameter, cryptoErr.Code)
	}
}

func TestEncrypt_InvalidNonceLength_Fails(t *testing.T) {
	svc := NewService()

	key, err := svc.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK returned error: %v", err)
	}

	_, err = svc.Encrypt(AEADEncryptInput{
		Algorithm: AlgorithmXChaCha20Poly1305,
		Key:       key,
		Nonce:     make([]byte, chacha20poly1305.NonceSizeX-1),
		Plaintext: []byte("payload"),
		AAD:       []byte(`{"kind":"payload"}`),
	})
	if err == nil {
		t.Fatalf("expected encrypt error with invalid nonce length")
	}

	cryptoErr, ok := err.(*common.Error)
	if !ok {
		t.Fatalf("expected *common.Error, got %T", err)
	}
	if cryptoErr.Code != ErrCodeInvalidParameter {
		t.Fatalf("expected error code %q, got %q", ErrCodeInvalidParameter, cryptoErr.Code)
	}
}

func TestDecrypt_InvalidKeyLength_Fails(t *testing.T) {
	svc := NewService()

	nonce, err := svc.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce returned error: %v", err)
	}

	_, err = svc.Decrypt(AEADDecryptInput{
		Algorithm:  AlgorithmXChaCha20Poly1305,
		Key:        make([]byte, chacha20poly1305.KeySize-1),
		Nonce:      nonce,
		Ciphertext: []byte("ciphertext"),
		AAD:        []byte(`{"kind":"payload"}`),
	})
	if err == nil {
		t.Fatalf("expected decrypt error with invalid key length")
	}

	cryptoErr, ok := err.(*common.Error)
	if !ok {
		t.Fatalf("expected *common.Error, got %T", err)
	}
	if cryptoErr.Code != ErrCodeInvalidParameter {
		t.Fatalf("expected error code %q, got %q", ErrCodeInvalidParameter, cryptoErr.Code)
	}
}

func TestDecrypt_InvalidNonceLength_Fails(t *testing.T) {
	svc := NewService()

	key, err := svc.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK returned error: %v", err)
	}

	_, err = svc.Decrypt(AEADDecryptInput{
		Algorithm:  AlgorithmXChaCha20Poly1305,
		Key:        key,
		Nonce:      make([]byte, chacha20poly1305.NonceSizeX-1),
		Ciphertext: []byte("ciphertext"),
		AAD:        []byte(`{"kind":"payload"}`),
	})
	if err == nil {
		t.Fatalf("expected decrypt error with invalid nonce length")
	}

	cryptoErr, ok := err.(*common.Error)
	if !ok {
		t.Fatalf("expected *common.Error, got %T", err)
	}
	if cryptoErr.Code != ErrCodeInvalidParameter {
		t.Fatalf("expected error code %q, got %q", ErrCodeInvalidParameter, cryptoErr.Code)
	}
}

func TestEncryptDecrypt_RandomizedRoundTrips(t *testing.T) {
	svc := NewService()

	for i := 0; i < 25; i++ {
		key, err := svc.GenerateDEK()
		if err != nil {
			t.Fatalf("iteration %d: GenerateDEK returned error: %v", i, err)
		}

		nonce, err := svc.GenerateNonce()
		if err != nil {
			t.Fatalf("iteration %d: GenerateNonce returned error: %v", i, err)
		}

		plaintext, err := svc.RandomBytes(32 + i)
		if err != nil {
			t.Fatalf("iteration %d: RandomBytes(plaintext) returned error: %v", i, err)
		}

		aad, err := svc.RandomBytes(8 + i)
		if err != nil {
			t.Fatalf("iteration %d: RandomBytes(aad) returned error: %v", i, err)
		}

		ciphertext, err := svc.Encrypt(AEADEncryptInput{
			Algorithm: AlgorithmXChaCha20Poly1305,
			Key:       key,
			Nonce:     nonce,
			Plaintext: plaintext,
			AAD:       aad,
		})
		if err != nil {
			t.Fatalf("iteration %d: Encrypt returned error: %v", i, err)
		}

		decrypted, err := svc.Decrypt(AEADDecryptInput{
			Algorithm:  AlgorithmXChaCha20Poly1305,
			Key:        key,
			Nonce:      nonce,
			Ciphertext: ciphertext,
			AAD:        aad,
		})
		if err != nil {
			t.Fatalf("iteration %d: Decrypt returned error: %v", i, err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("iteration %d: decrypted bytes do not match plaintext", i)
		}
	}
}

func TestDecrypt_WithTamperedCiphertext_Fails(t *testing.T) {
	svc := NewService()

	key, err := svc.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK returned error: %v", err)
	}

	nonce, err := svc.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce returned error: %v", err)
	}

	plaintext := []byte("payload-data")
	aad := []byte(`{"kind":"payload"}`)

	ciphertext, err := svc.Encrypt(AEADEncryptInput{
		Algorithm: AlgorithmXChaCha20Poly1305,
		Key:       key,
		Nonce:     nonce,
		Plaintext: plaintext,
		AAD:       aad,
	})
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Fatalf("ciphertext must not be empty")
	}

	tampered := append([]byte(nil), ciphertext...)
	tampered[0] ^= 0x01

	_, err = svc.Decrypt(AEADDecryptInput{
		Algorithm:  AlgorithmXChaCha20Poly1305,
		Key:        key,
		Nonce:      nonce,
		Ciphertext: tampered,
		AAD:        aad,
	})
	if err == nil {
		t.Fatalf("expected decrypt error with tampered ciphertext")
	}

	cryptoErr, ok := err.(*common.Error)
	if !ok {
		t.Fatalf("expected *common.Error, got %T", err)
	}
	if cryptoErr.Code != ErrCodeAuthFailed {
		t.Fatalf("expected error code %q, got %q", ErrCodeAuthFailed, cryptoErr.Code)
	}
}

func TestDecrypt_WithTamperedTag_Fails(t *testing.T) {
	svc := NewService()

	key, err := svc.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK returned error: %v", err)
	}

	nonce, err := svc.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce returned error: %v", err)
	}

	plaintext := []byte("payload-data")
	aad := []byte(`{"kind":"payload"}`)

	ciphertext, err := svc.Encrypt(AEADEncryptInput{
		Algorithm: AlgorithmXChaCha20Poly1305,
		Key:       key,
		Nonce:     nonce,
		Plaintext: plaintext,
		AAD:       aad,
	})
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Fatalf("ciphertext must not be empty")
	}

	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 0x01

	_, err = svc.Decrypt(AEADDecryptInput{
		Algorithm:  AlgorithmXChaCha20Poly1305,
		Key:        key,
		Nonce:      nonce,
		Ciphertext: tampered,
		AAD:        aad,
	})
	if err == nil {
		t.Fatalf("expected decrypt error with tampered authentication tag")
	}

	cryptoErr, ok := err.(*common.Error)
	if !ok {
		t.Fatalf("expected *common.Error, got %T", err)
	}
	if cryptoErr.Code != ErrCodeAuthFailed {
		t.Fatalf("expected error code %q, got %q", ErrCodeAuthFailed, cryptoErr.Code)
	}
}
