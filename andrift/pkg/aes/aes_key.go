package aes

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
)

// TODO: Generate a randoms array of byte for 'size' bytes (16, 24, 32) secret key for aes
func AesSecretKeyGen(size int) ([]byte, error) {
	if size != 16 && size != 24 && size != 32 {
		return nil, errors.New("invalid key size")
	}

	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// TODO: Import a key from a base64 format storing
func ImportKeyFromFile(filepath string) ([]byte, error) {
	// Read the key file
	keyData, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Decode the key from Base64
	key, err := base64.StdEncoding.DecodeString(string(keyData))
	if err != nil {
		return nil, fmt.Errorf("failed to decode key from Base64: %w", err)
	}

	return key, nil
}
