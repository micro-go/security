package security

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// Encrypt() func encrypts the message given a default 32-byte basekey and some salt value.
func Encrypt(key, message string) (encmess string, err error) {
	return EncryptBytes(key, []byte(message), nil)
}

// Decrypt() func decrypts the message given a default 32-byte basekey and some salt value.
func Decrypt(key, securemess string) (decodedmess string, err error) {
	cipherText, err := base64.URLEncoding.DecodeString(securemess)
	if err != nil {
		return
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return
	}

	if len(cipherText) < aes.BlockSize {
		err = errors.New("Ciphertext block size is too short!")
		return
	}

	// IV needs to be unique, but doesn't have to be secure.
	// It's common to put it at the beginning of the ciphertext.
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(cipherText, cipherText)
	decodedmess = string(cipherText)
	return
}

// EncryptBytesPkcs7() func encrypts the message given a default 32-byte basekey and some salt value.
func EncryptBytes(key string, message []byte, opts *Opts) (encmess string, err error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return
	}

	if opts != nil {
		err = nil
		switch opts.Padding {
		case PaddingPkcs7:
			message, err = pkcs7Padding(message, block.BlockSize())
		}
		if err != nil {
			return "", err
		}
	}

	// IV needs to be unique, but doesn't have to be secure.
	// It's common to put it at the beginning of the ciphertext.
	cipherText := make([]byte, aes.BlockSize+len(message))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], message)

	encmess = base64.URLEncoding.EncodeToString(cipherText)
	return
}

// From https://github.com/apexskier/cryptoPadding
func pkcs7Padding(data []byte, blockSize int) (output []byte, err error) {
	if blockSize < 1 || blockSize >= 256 {
		return output, fmt.Errorf("blocksize is out of bounds: %v", blockSize)
	}
	var paddingBytes = padSize(len(data), blockSize)
	paddingSlice := bytes.Repeat([]byte{byte(paddingBytes)}, paddingBytes)
	output = append(data, paddingSlice...)
	return output, nil
}

func padSize(dataSize, blockSize int) (ps int) {
	ps = blockSize - (dataSize % blockSize)
	if ps == 0 {
		ps = blockSize
	}
	return
}
