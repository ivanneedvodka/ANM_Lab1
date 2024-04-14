package aes

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
)

// TODO: Generate a random array of bytes for 'size' bytes (16, 24, 32) secret key for AES
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

// EncodeKeyToBase64 encodes the provided key to a Base64 string
func EncodeKeyToBase64(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// WriteKeyToFile writes the provided key to a file
func WriteKeyToFile(key []byte, filepath string) error {
	// Encode the key to Base64
	encodedKey := EncodeKeyToBase64(key)

	// Write the encoded key to the file
	err := os.WriteFile(filepath, []byte(encodedKey), 0644)
	if err != nil {
		return fmt.Errorf("failed to write key to file: %w", err)
	}

	return nil
}
