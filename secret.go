package onetimepasscode

import (
	"crypto/rand"
)

// GenerateRandomBytes generates a secure random array
// of byteLen bytes.
func GenerateRandomBytes(byteLen int) ([]byte, error) {
	b := make([]byte, byteLen)
	_, err := rand.Read(b)

	if err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateSecureSecret generates a secure random seed
// of recommended byte length.
//
// The length of the shared secret MUST be at least 128 bits.
// RFC4226 RECOMMENDs a shared secret length of 160 bits.
func GenerateSecureSecret() ([]byte, error) {
	bytes, err := GenerateRandomBytes(160)
	return bytes, err
}
