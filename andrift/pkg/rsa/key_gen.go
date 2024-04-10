package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func GenerateRSAKeyPair(keySize int, privateKeyFilePath, publicKeyFilePath string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return fmt.Errorf("failed to generate RSA private key: %w", err)
	}

	if privateKeyFilePath == "" {
		privateKeyFilePath = "private_key.pem"
	}
	if err := writePrivateKeyToFile(privateKey, privateKeyFilePath); err != nil {
		return fmt.Errorf("failed to write private key to file: %w", err)
	}

	if publicKeyFilePath == "" {
		publicKeyFilePath = "public_key.pem"
	}
	if err := writePublicKeyToFile(&privateKey.PublicKey, publicKeyFilePath); err != nil {
		return fmt.Errorf("failed to write public key to file: %w", err)
	}

	return nil
}

func writePrivateKeyToFile(privateKey *rsa.PrivateKey, privateKeyFilePath string) error {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	privateKeyFile, err := os.Create(privateKeyFilePath)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer privateKeyFile.Close()

	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return fmt.Errorf("failed to write private key to file: %w", err)
	}

	return nil
}

func writePublicKeyToFile(publicKey *rsa.PublicKey, publicKeyFilePath string) error {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	publicKeyFile, err := os.Create(publicKeyFilePath)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer publicKeyFile.Close()

	if err := pem.Encode(publicKeyFile, publicKeyPEM); err != nil {
		return fmt.Errorf("failed to write public key to file: %w", err)
	}

	return nil
}
