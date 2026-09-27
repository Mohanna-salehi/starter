package cryptoKey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func Encrypt(value string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	cipherTxt := gcm.Seal(
		nil,
		nonce,
		[]byte(value),
		nil,
	)

	data := append(nonce, cipherTxt...)

	return base64.StdEncoding.EncodeToString(data), nil
}

func Decrypt(value string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()

	if len(data) < nonceSize {
		return "", fmt.Errorf("invalid encrypted value")
	}

	nonce := data[:nonceSize]
	cipherTxt := data[nonceSize:]

	plainTxt, err := gcm.Open(
		nil,
		nonce,
		cipherTxt,
		nil,
	)
	if err != nil {
		return "", err
	}

	return string(plainTxt), nil
}

func DecodeKey(encodedKey string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, err
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes")
	}

	return key, nil
}
