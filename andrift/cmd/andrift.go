package main

import (
	"andrift/pkg/aes"
	"andrift/pkg/rsa"
	"fmt"
)

func main() {
	// AES test
	aesKey, err := aes.AesSecretKeyGen(24)
	if err != nil {
		fmt.Printf("Error %v", err)
	}

	err = aes.AesFileEncrypt("data.txt", "aesEncryptedData.txt", aesKey)
	fmt.Println(err)
	err = aes.AesFileDecrypt("aesEncryptedData.txt", "aesDecryptedData.txt", aesKey)
	fmt.Println(err)

	// RSA Test
	err = rsa.GenerateRSAKeyPair(1024, "", "")
	fmt.Println(err)
	err = rsa.RsaFileEncrypt("public_key.pem", "data.txt", "rsaEncryptedFile.txt")
	fmt.Println(err)
	err = rsa.RsaFileDecrypt("private_key.pem", "rsaEncryptedFile.txt", "rsaDecryptedFile.txt")
	fmt.Println(err)
}
