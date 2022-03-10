package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

//加密字符串
func GcmEncrypt(key, plaintext string) (string, error) {
	if len(key) != 32 && len(key) != 24 && len(key) != 16 {
		return "", errors.New("the length of key is error")
	}

	if len(plaintext) < 1 {
		return "", errors.New("plaintext is null")
	}

	keyByte := []byte(key)
	plainByte:=[]byte(plaintext)

	block, err := aes.NewCipher(keyByte)
	if err != nil {
		return "", err
	}

	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	seal := aesGcm.Seal(nonce, nonce, plainByte, nil)
	return base64.URLEncoding.EncodeToString(seal), nil
}

//解密字符串
func GcmDecrypt(key, cipherText string) (string, error) {
	if len(key) != 32 && len(key) != 24 && len(key) != 16 {
		return "", errors.New("the length of key is error")
	}

	if len(cipherText) < 1 {
		return "", errors.New("cipherText is null")
	}

	cipherByte, err := base64.URLEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	if len(cipherByte) < 12 {
		return "", errors.New("cipherByte is error")
	}

	nonce, cipherByte := cipherByte[:12], cipherByte[12:]

	keyByte := []byte(key)
	block, err := aes.NewCipher(keyByte)
	if err != nil {
		return "", err
	}

	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plainByte, err := aesGcm.Open(nil, nonce, cipherByte, nil)
	if err != nil {
		return "", err
	}

	return string(plainByte), nil
}

//生成32位md5字串
func GetAesKey(s string) string {
		h := md5.New()
		h.Write([]byte(s))
		return hex.EncodeToString(h.Sum(nil))

}
