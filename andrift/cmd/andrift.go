package main

import (
	"andrift/pkg/aes"
	"andrift/pkg/rsa"
	"bufio"
	"fmt"
	"os"
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
			generateKey()
		case 4:
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
	fmt.Println("3. Generate a key")
	fmt.Println("4. Exit")
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

func encryptFile() {
	fmt.Println("Encrypting a file...")
	fmt.Print("Enter the path to the file: ")
	filePath, err := getUserInput()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Prompt for encryption algorithm
	fmt.Println("Choose encryption algorithm:")
	fmt.Println("1. AES")
	fmt.Println("2. RSA")
	fmt.Print("Enter your choice: ")
	algorithmChoice := getUserChoice()

	switch algorithmChoice {
	case 1:
		fmt.Println("You chose AES for encryption.")
		aesKey, err := aes.AesSecretKeyGen(24)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		err = aes.AesFileEncrypt(filePath, "aesEncryptedData.txt", aesKey)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Println("File encrypted using AES.")
	case 2:
		fmt.Println("You chose RSA for encryption.")
		err := rsa.GenerateRSAKeyPair(1024, "", "")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		err = rsa.RsaFileEncrypt("public_key.pem", filePath, "rsaEncryptedFile.txt")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Println("File encrypted using RSA.")
	default:
		fmt.Println("Invalid choice. Encryption aborted.")
	}
}

func decryptFile() {
	fmt.Println("Decrypting a file...")
	fmt.Print("Enter the path to the file: ")
	filePath, err := getUserInput()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Prompt for decryption algorithm
	fmt.Println("Choose decryption algorithm:")
	fmt.Println("1. AES")
	fmt.Println("2. RSA")
	fmt.Print("Enter your choice: ")
	algorithmChoice := getUserChoice()

	switch algorithmChoice {
	case 1:
		fmt.Println("You chose AES for decryption.")
		aesKey, err := aes.AesSecretKeyGen(24)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		err = aes.AesFileDecrypt(filePath, "aesDecryptedData.txt", aesKey)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Println("File decrypted using AES.")
	case 2:
		fmt.Println("You chose RSA for decryption.")
		err := rsa.RsaFileDecrypt("private_key.pem", filePath, "rsaDecryptedFile.txt")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Println("File decrypted using RSA.")
	default:
		fmt.Println("Invalid choice. Decryption aborted.")
	}
}

func generateKey() {
	fmt.Println("Generating a key...")
	err := rsa.GenerateRSAKeyPair(1024, "", "")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Println("Key generated.")
}

func getUserInput() (string, error) {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return scanner.Text(), nil
}
