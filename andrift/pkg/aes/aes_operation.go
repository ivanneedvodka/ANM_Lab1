package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

func AesFileEncrypt(inFilePath, outFilePath string, secret_key []byte) error {
	// TODO: First check for input file existence
	inFile, err := os.Open(inFilePath)
	if err != nil {
		return fmt.Errorf("cannot open file with path %s", inFilePath)
	}

	defer inFile.Close()

	// TODO: create encrypted file
	outFile, err := os.Create(outFilePath)
	if err != nil {
		return fmt.Errorf("cannot create new file in %s", outFilePath)
	}

	defer outFile.Close()

	// TODO: Create AES Cipher block for encryption process
	block, err := aes.NewCipher(secret_key)
	if err != nil {
		return fmt.Errorf("cannot use input secret_key: %v", err)
	}

	iv, err := generateIV()
	if err != nil {
		return err
	}

	// First write IV to the file for later decryption
	_, err = outFile.Write(iv)
	if err != nil {
		return fmt.Errorf("failed to write IV to output file: %w", err)
	}

	// Create a stream cipher using the AES block and IV
	stream := cipher.NewCFBEncrypter(block, iv)

	// Encrypt and write the input file content to the output file
	_, err = io.Copy(outFile, &cipher.StreamReader{S: stream, R: inFile})
	if err != nil {
		return fmt.Errorf("failed to encrypt and write file content: %w", err)
	}

	return nil
}

func generateIV() ([]byte, error) {
	// TOOD: generate IV for better randomization
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("failed to generate IV for encrypt process %v", err)
	}

	return iv, nil
}

func AesFileDecrypt(inFilePath, outFilePath string, secretKey []byte) error {
	inFile, err := os.Open(inFilePath)
	if err != nil {
		return fmt.Errorf("cannot open file with path %s: %w", inFilePath, err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outFilePath)
	if err != nil {
		return fmt.Errorf("cannot create new file in %s: %w", outFilePath, err)
	}
	defer outFile.Close()

	iv := make([]byte, aes.BlockSize)
	_, err = inFile.Read(iv)
	if err != nil {
		return fmt.Errorf("failed to read IV from input file: %w", err)
	}

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return fmt.Errorf("cannot use input secret_key: %v", err)
	}

	stream := cipher.NewCFBDecrypter(block, iv)

	_, err = io.Copy(outFile, &cipher.StreamReader{S: stream, R: inFile})
	if err != nil {
		return fmt.Errorf("failed to decrypt and write file content: %w", err)
	}

	return nil
}
