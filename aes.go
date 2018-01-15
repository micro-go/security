package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// func Encrypt() encrypts the message given a default 32-byte basekey and some salt value.
func Encrypt(basekey, salt, message string) (encmess string, err error) {
	key := saltKey(basekey, salt)
	plainText := []byte(message)

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	//returns to base64 encoded string
	encmess = base64.URLEncoding.EncodeToString(cipherText)
	return
}

// func Decrypt() decrypts the message given a default 32-byte basekey and some salt value.
func Decrypt(basekey, salt, securemess string) (decodedmess string, err error) {
	cipherText, err := base64.URLEncoding.DecodeString(securemess)
	if err != nil {
		return
	}

	key := saltKey(basekey, salt)
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return
	}

	if len(cipherText) < aes.BlockSize {
		err = errors.New("Ciphertext block size is too short!")
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(cipherText, cipherText)

	decodedmess = string(cipherText)
	return
}

func saltKey(key, salt string) string {
	if len(key) != 32 {
		panic("AES encryption requires 32-byte key")
	}
	if len(salt) >= 32 {
		return salt[:32]
	}
	return salt + key[len(salt):]
}