// Package aes
// 封装AES的基础操作，完成数据的aes加解密
package aes

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
)

// Crypto Aes加解密相关接口
type Crypto interface {
	// Encrypt 加密数据
	Encrypt(origStr string) (string, error)

	// Decrypt 解密数据
	Decrypt(decryptedData string) (string, error)

	// PaddingType 设置padding方式
	PaddingType(tp aesPaddingType)

	// EncryptModel 设置加密模式
	EncryptModel(model aesEncryptModel)
}

// aes内部数据结构
type data struct {
	// aes加密密钥
	key          []byte
	iv           []byte
	paddingType  aesPaddingType
	encryptModel aesEncryptModel
}

type Conf struct {
	Key          string
	IV           string
	PaddingType  aesPaddingType
	EncryptModel aesEncryptModel
}

func New(c Conf) Crypto {
	if len(c.Key) <= 0 {
		panic("key cannot be empty")
	}

	obj := new(data)
	obj.key = []byte(c.Key)
	obj.iv = []byte(c.IV)
	if len(obj.iv) <= 0 {
		obj.iv = obj.key
	}
	obj.paddingType = c.PaddingType
	obj.encryptModel = c.EncryptModel
	return obj
}

func (obj *data) PaddingType(tp aesPaddingType) {
	obj.paddingType = tp
}

func (obj *data) EncryptModel(model aesEncryptModel) {
	obj.encryptModel = model
}

// Encrypt AES加密
func (obj *data) Encrypt(origStr string) (ret string, err error) {
	defer func() {
		if p := recover(); p != nil {
			if e, ok := p.(error); ok {
				err = e
			} else {
				err = fmt.Errorf("encrypt err: %v", p)
			}
		}
	}()

	if origStr == "" {
		return "", nil
	}

	block, err := aes.NewCipher(obj.key)
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	origData := []byte(origStr)
	origData = padding(origData, blockSize, obj.paddingType)

	cryptData, err := aesEncrypt(block, obj.iv, origData, obj.encryptModel)
	if err != nil {
		return "", err
	}
	retStr := base64.StdEncoding.EncodeToString(cryptData)
	return retStr, nil
}

// Decrypt AES解密
func (obj *data) Decrypt(decryptedData string) (ret string, err error) {
	defer func() {
		if p := recover(); p != nil {
			if e, ok := p.(error); ok {
				err = e
			} else {
				err = fmt.Errorf("decrypt err: %v", p)
			}
		}
	}()

	if decryptedData == "" {
		return "", nil
	}

	block, err := aes.NewCipher(obj.key)
	if err != nil {
		return "", err
	}
	// blockSize := block.BlockSize()

	retStr, err := base64.StdEncoding.DecodeString(decryptedData)
	if err != nil {
		return "", err
	}

	origData, err := aesDecrypt(block, obj.iv, retStr, obj.encryptModel)
	if err != nil {
		return "", err
	}

	origData = unPadding(origData, obj.paddingType)
	return string(origData), nil
}
