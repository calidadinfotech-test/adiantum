package main

import (
	"crypto/aes"
	"errors"
	"fmt"
)

type AES struct {
	keyLength int
}

// NewAES creates a new AES cipher.
// Default is AES-128 (16-byte key).
func NewAES() *AES {
	return &AES{
		keyLength: 16,
	}
}

// SetKeyLen sets the key length.
// 16 = AES-128
// 24 = AES-192
// 32 = AES-256
func (a *AES) SetKeyLen(k int) error {
	if k != 16 && k != 24 && k != 32 {
		return errors.New("invalid AES key length")
	}

	a.keyLength = k
	return nil
}

// VariantName returns AES128, AES192, or AES256.
func (a *AES) VariantName() string {
	return fmt.Sprintf("AES%d", a.keyLength*8)
}

// Variants returns all supported AES key lengths.
func (a *AES) Variants() []int {
	return []int{16, 24, 32}
}

// Encrypt encrypts data using AES-ECB.
func (a *AES) Encrypt(pt []byte, key []byte) ([]byte, error) {

	if len(key) != a.keyLength {
		return nil, fmt.Errorf(
			"invalid key length: expected %d bytes, got %d bytes",
			a.keyLength,
			len(key),
		)
	}

	if len(pt)%aes.BlockSize != 0 {
		return nil, fmt.Errorf(
			"plaintext length must be a multiple of %d bytes",
			aes.BlockSize,
		)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ct := make([]byte, len(pt))

	// AES ECB encrypts every block independently.
	for i := 0; i < len(pt); i += aes.BlockSize {
		block.Encrypt(
			ct[i:i+aes.BlockSize],
			pt[i:i+aes.BlockSize],
		)
	}

	return ct, nil
}

// Decrypt decrypts data using AES-ECB.
func (a *AES) Decrypt(ct []byte, key []byte) ([]byte, error) {

	if len(key) != a.keyLength {
		return nil, fmt.Errorf(
			"invalid key length: expected %d bytes, got %d bytes",
			a.keyLength,
			len(key),
		)
	}

	if len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf(
			"ciphertext length must be a multiple of %d bytes",
			aes.BlockSize,
		)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	pt := make([]byte, len(ct))

	// AES ECB decrypts every block independently.
	for i := 0; i < len(ct); i += aes.BlockSize {
		block.Decrypt(
			pt[i:i+aes.BlockSize],
			ct[i:i+aes.BlockSize],
		)
	}

	return pt, nil
}
