package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

func encrypt(data []byte, passphrase string) ([]byte, error) {
	block, err := aes.NewCipher(createHash(passphrase))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func decrypt(data []byte, passphrase string) ([]byte, error) {
	block, err := aes.NewCipher(createHash(passphrase))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func createHash(key string) []byte {
	hash := sha256.Sum256([]byte(key))
	return hash[:]
}

func generatePassphrase(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <option> [<file> <passphrase>]")
		fmt.Println("Options: encrypt, decrypt, generate-passphrase")
		return
	}

	option := os.Args[1]

	switch option {
	case "encrypt":
		if len(os.Args) < 4 {
			fmt.Println("Usage: go run main.go encrypt <file> <passphrase>")
			return
		}
		filepath := os.Args[2]
		passphrase := os.Args[3]

		data, err := ioutil.ReadFile(filepath)
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}

		encryptedData, err := encrypt(data, passphrase)
		if err != nil {
			fmt.Println("Error encrypting file:", err)
			return
		}

		err = ioutil.WriteFile(filepath+".enc", encryptedData, 0644)
		if err != nil {
			fmt.Println("Error writing encrypted file:", err)
			return
		}

		fmt.Println("File encrypted successfully.")
	case "decrypt":
		if len(os.Args) < 4 {
			fmt.Println("Usage: go run main.go decrypt <file> <passphrase>")
			return
		}
		filepath := os.Args[2]
		passphrase := os.Args[3]

		data, err := ioutil.ReadFile(filepath)
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}

		decryptedData, err := decrypt(data, passphrase)
		if err != nil {
			fmt.Println("Error decrypting file:", err)
			return
		}

		err = ioutil.WriteFile(filepath+".dec", decryptedData, 0644)
		if err != nil {
			fmt.Println("Error writing decrypted file:", err)
			return
		}

		fmt.Println("File decrypted successfully.")
	case "generate-passphrase":
		passphrase, err := generatePassphrase(32) // 32 bytes will give us a 256-bit key
		if err != nil {
			fmt.Println("Error generating passphrase:", err)
			return
		}
		fmt.Println("Generated passphrase:", passphrase)
	default:
		fmt.Println("Invalid option. Use 'encrypt', 'decrypt', or 'generate-passphrase'.")
	}
}
