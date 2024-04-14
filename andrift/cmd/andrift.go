package main

import (
	"andrift/pkg/aes"
	"andrift/pkg/rsa"
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

const (
	MAX_SECRET_KEY_SIZE = 32
	RSA_KEY_SIZE        = 2048
)

func main() {
	for {
		displayMenu()
		choice := getUserChoice()
		switch choice {
		case 1:
			encryptFile()
		case 2:
			decryptFile()
		case 3:
			fmt.Println("Exiting the program...")
			os.Exit(0)
		default:
			fmt.Println("Invalid choice. Please try again.")
		}
	}
}

func displayMenu() {
	fmt.Println("Menu:")
	fmt.Println("1. Encrypt a file")
	fmt.Println("2. Decrypt a file")
	fmt.Println("3. Exit")
}

func getUserChoice() int {
	var choice int
	fmt.Print("Enter your choice: ")
	_, err := fmt.Scan(&choice)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	return choice
}

func getUserInput() (string, error) {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return scanner.Text(), nil
}

func encryptFile() {
	fmt.Println("Path to your file: ")
	filePath, err := getUserInput()
	if err != nil {
		fmt.Printf("Error on I/O: %v\n", err)
		return
	}

	// TODOL Generate a random secret key for AES Encryption
	secret_key, err := aes.AesSecretKeyGen(MAX_SECRET_KEY_SIZE)
	if err != nil {
		fmt.Printf("Error on generate new secret key: %v\n", err)
		return
	}

	encryptFilePath := fmt.Sprintf("%s.enc", filePath)
	err = aes.AesFileEncrypt(filePath, encryptFilePath, secret_key)
	if err != nil {
		fmt.Printf("Error on file encryption process: %v", err)
		return
	}

	fmt.Printf("File in %s have been encrypted successfully to %s\n", filePath, encryptFilePath)

	// TODO: generate a RSA key pair to encrypt the secret key
	privateKeyPath := fmt.Sprintf("%s.priv", filePath)
	publicKeyPath := fmt.Sprintf("%s.pub", filePath)

	err = rsa.GenerateRSAKeyPair(RSA_KEY_SIZE, privateKeyPath, publicKeyPath)
	if err != nil {
		fmt.Printf("Failed to generate RSA key pair: %v\n", err)
		return
	}

	// Generate checksum of the private key file
	checksumPath := fmt.Sprintf("%s.checksum", privateKeyPath)
	err = generateChecksum(privateKeyPath, checksumPath)
	if err != nil {
		fmt.Printf("Failed to generate checksum: %v\n", err)
		return
	}

	fmt.Printf("Successfully generated key pair. Your key pair is located in:\nPrivate: %s\nPublic: %s\nChecksum: %s\n", privateKeyPath, publicKeyPath, checksumPath)

	secretKeyPath := fmt.Sprintf("%s.sec", filePath)
	err = aes.WriteKeyToFile(secret_key, secretKeyPath)
	if err != nil {
		fmt.Printf("failed to save key: %v\n", err)
		return
	}

	// TODO: Encrypt the secret key with public key
	encryptedSecretKeyPath := fmt.Sprintf("%s.enc", secretKeyPath)
	err = rsa.RsaFileEncrypt(publicKeyPath, secretKeyPath, encryptedSecretKeyPath)
	if err != nil {
		fmt.Printf("Failed to encrypt secret key: %v\n", err)
		return
	}

	fmt.Printf("Secret key encrypted successfully, see the encrypted file at %s\n", encryptedSecretKeyPath)
	fmt.Printf("Clean up...\n")

	// TODO: remove the secretKeyPath file
	err = os.Remove(secretKeyPath)
	if err != nil {
		fmt.Printf("Failed to delete the clear secret key file: %v\n", err)
		return
	}

	fmt.Printf("Secret key file %s has been deleted\n", secretKeyPath)
}

func decryptFile() {
	fmt.Println("Encrypted file path: ")
	encryptedFilePath, err := getUserInput()
	if err != nil {
		fmt.Printf("Error on I/O: %v", err)
		return
	}

	fmt.Println("Private key file path: ")
	privateKeyPath, err := getUserInput()
	if err != nil {
		fmt.Printf("Error on I/O: %v\n", err)
		return
	}

	// Checksum verification
	checksumPath := fmt.Sprintf("%s.checksum", privateKeyPath)
	err = verifyChecksum(privateKeyPath, checksumPath)
	if err != nil {
		fmt.Printf("Failed to verify checksum: %v\n", err)
		return
	}

	// Decrypt the secret key
	encryptedSecretKeyPath := fmt.Sprintf("%s.sec.enc", privateKeyPath[0:len(privateKeyPath)-5])
	secretKeyPath := fmt.Sprintf("%s.sec", privateKeyPath[0:len(privateKeyPath)-5])
	err = rsa.RsaFileDecrypt(privateKeyPath, encryptedSecretKeyPath, secretKeyPath)
	if err != nil {
		fmt.Printf("Failed to decrypt secret key: %v\n", err)
		return
	}

	// Read the secret key
	secretKey, err := aes.ImportKeyFromFile(secretKeyPath)
	if err != nil {
		fmt.Printf("Failed to read secret key: %v\n", err)
		return
	}

	// Decrypt the original file
	decryptedFilePath := fmt.Sprintf("%s.dec", encryptedFilePath)
	err = aes.AesFileDecrypt(encryptedFilePath, decryptedFilePath, secretKey)
	if err != nil {
		fmt.Printf("Error on file decryption process: %v", err)
		return
	}

	fmt.Printf("File %s has been decrypted successfully to %s\n", encryptedFilePath, decryptedFilePath)

	// Cleanup: Remove the decrypted secret key file
	err = os.Remove(secretKeyPath)
	if err != nil {
		fmt.Printf("Failed to delete the decrypted secret key file: %v\n", err)
		return
	}

	fmt.Printf("Decrypted secret key file %s has been deleted\n", secretKeyPath)
}

func verifyChecksum(filePath, checksumPath string) error {
	hash := sha256.New()
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(hash, file)
	if err != nil {
		return err
	}

	checksum := hash.Sum(nil)
	checksumStr := hex.EncodeToString(checksum)

	savedChecksumBytes, err := os.ReadFile(checksumPath)
	if err != nil {
		return err
	}

	savedChecksumStr := string(savedChecksumBytes)

	if checksumStr != savedChecksumStr {
		return fmt.Errorf("checksum verification failed")
	}

	return nil
}

func generateChecksum(filePath, checksumPath string) error {
	hash := sha256.New()
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(hash, file)
	if err != nil {
		return err
	}

	checksum := hash.Sum(nil)
	checksumStr := hex.EncodeToString(checksum)

	err = os.WriteFile(checksumPath, []byte(checksumStr), 0644)
	if err != nil {
		return err
	}

	return nil
}
