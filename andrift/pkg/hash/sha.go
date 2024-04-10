package hash

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func CalculateSHA1String(input string) (string, error) {
	hash := sha1.New()
	_, err := io.WriteString(hash, input)
	if err != nil {
		return "", fmt.Errorf("failed to calculate SHA-1 hash: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func CalculateSHA256String(input string) (string, error) {
	hash := sha256.New()
	_, err := io.WriteString(hash, input)
	if err != nil {
		return "", fmt.Errorf("failed to calculate SHA-256 hash: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func CalculateSHA1File(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash := sha1.New()
	_, err = io.Copy(hash, file)
	if err != nil {
		return "", fmt.Errorf("failed to calculate SHA-1 hash: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func CalculateSHA256File(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	_, err = io.Copy(hash, file)
	if err != nil {
		return "", fmt.Errorf("failed to calculate SHA-256 hash: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
