package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

func RsaFileEncrypt(publicKeyFilePath, inputFilePath, outputFile string) error {
	publicKeyFile, err := os.Open(publicKeyFilePath)
	if err != nil {
		return fmt.Errorf("failed to open public key file: %w", err)
	}
	defer publicKeyFile.Close()

	inputFile, err := os.ReadFile(inputFilePath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}

	publicKeyPEM, err := io.ReadAll(publicKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read public key file: %w", err)
	}

	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey.(*rsa.PublicKey), []byte(inputFile))
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	outputFileHandle, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFileHandle.Close()

	_, err = outputFileHandle.Write(encryptedData)
	if err != nil {
		return fmt.Errorf("failed to write encrypted data to output file: %w", err)
	}

	return nil
}

func RsaFileDecrypt(privateKeyFilePath, inputFile, outputFile string) error {
	privateKeyFile, err := os.Open(privateKeyFilePath)
	if err != nil {
		return fmt.Errorf("failed to open private key file: %w", err)
	}
	defer privateKeyFile.Close()

	privateKeyPEM, err := io.ReadAll(privateKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	encryptedData, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	decryptedData, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedData)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}

	outputFileHandle, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFileHandle.Close()

	_, err = outputFileHandle.Write(decryptedData)
	if err != nil {
		return fmt.Errorf("failed to write decrypted data to output file: %w", err)
	}

	return nil
}
