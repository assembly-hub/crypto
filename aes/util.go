package aes

import (
	"bytes"
	"crypto/cipher"

	"github.com/assembly-hub/basics/util"

	"github.com/assembly-hub/crypto/aes/ecb"
)

func aesEncrypt(block cipher.Block, iv []byte, origData []byte, model aesEncryptModel) (ret []byte, err error) {
	switch model {
	case CBC:
		return cbcEncrypt(block, iv, origData), nil
	case ECB:
		return ecbEncrypt(block, iv, origData), nil
	case CTR:
		return ctrEncrypt(block, iv, origData), nil
	case OFB:
		return ofbEncrypt(block, iv, origData), nil
	case CFB:
		return cfbEncrypt(block, iv, origData), nil
	default:
		panic("encrypt model error")
	}
}

func cbcEncrypt(block cipher.Block, iv []byte, origData []byte) (ret []byte) {
	blockMode := cipher.NewCBCEncrypter(block, iv)
	ret = make([]byte, len(origData))
	blockMode.CryptBlocks(ret, origData)
	return
}

func ecbEncrypt(block cipher.Block, iv []byte, origData []byte) (ret []byte) {
	blockMode := ecb.NewECBEncrypt(block)
	ret = make([]byte, len(origData))
	blockMode.CryptBlocks(ret, origData)
	return
}

func ctrEncrypt(block cipher.Block, iv []byte, origData []byte) (ret []byte) {
	stream := cipher.NewCTR(block, iv)
	ret = make([]byte, len(origData))
	stream.XORKeyStream(ret, origData)
	return
}

func ofbEncrypt(block cipher.Block, iv []byte, origData []byte) (ret []byte) {
	stream := cipher.NewOFB(block, iv)
	ret = make([]byte, len(origData))
	stream.XORKeyStream(ret, origData)
	return
}

func cfbEncrypt(block cipher.Block, iv []byte, origData []byte) (ret []byte) {
	stream := cipher.NewCFBEncrypter(block, iv)
	ret = make([]byte, len(origData))
	stream.XORKeyStream(ret, origData)
	return
}

func aesDecrypt(block cipher.Block, iv []byte, decryptedData []byte, model aesEncryptModel) (ret []byte, err error) {
	switch model {
	case CBC:
		return cbcDecrypt(block, iv, decryptedData), nil
	case ECB:
		return ecbDecrypt(block, iv, decryptedData), nil
	case CTR:
		return ctrDecrypt(block, iv, decryptedData), nil
	case OFB:
		return ofbDecrypt(block, iv, decryptedData), nil
	case CFB:
		return cfbDecrypt(block, iv, decryptedData), nil
	default:
		panic("encrypt model error")
	}
}

func cbcDecrypt(block cipher.Block, iv []byte, decryptedData []byte) (ret []byte) {
	blockMode := cipher.NewCBCDecrypter(block, iv)
	ret = make([]byte, len(decryptedData))
	blockMode.CryptBlocks(ret, decryptedData)
	return
}

func ecbDecrypt(block cipher.Block, iv []byte, decryptedData []byte) (ret []byte) {
	blockMode := ecb.NewECBDecrypt(block)
	ret = make([]byte, len(decryptedData))
	blockMode.CryptBlocks(ret, decryptedData)
	return
}

func ctrDecrypt(block cipher.Block, iv []byte, decryptedData []byte) (ret []byte) {
	stream := cipher.NewCTR(block, iv)
	ret = make([]byte, len(decryptedData))
	stream.XORKeyStream(ret, decryptedData)
	return
}

func ofbDecrypt(block cipher.Block, iv []byte, decryptedData []byte) (ret []byte) {
	stream := cipher.NewOFB(block, iv)
	ret = make([]byte, len(decryptedData))
	stream.XORKeyStream(ret, decryptedData)
	return
}

func cfbDecrypt(block cipher.Block, iv []byte, decryptedData []byte) (ret []byte) {
	stream := cipher.NewCFBDecrypter(block, iv)
	ret = make([]byte, len(decryptedData))
	stream.XORKeyStream(ret, decryptedData)
	return
}

// 补充数据，达到block size的整数倍
func padding(ciphertext []byte, blockSize int, tp aesPaddingType) []byte {
	switch tp {
	case PKCS7:
		return pkcs7Padding(ciphertext, blockSize)
	case Zero:
		return zeroPadding(ciphertext, blockSize)
	case ISO10126:
		return iso10126Padding(ciphertext, blockSize)
	case ISO9797M1:
		return iso9797m1Padding(ciphertext, blockSize)
	case ISO9797M2:
		return iso9797m2Padding(ciphertext, blockSize)
	case ANSIX923:
		return ansix923Padding(ciphertext, blockSize)
	case NoOrZero:
		return noPadding(ciphertext, blockSize, true)
	case No:
		return noPadding(ciphertext, blockSize, false)
	default:
		panic("padding type error")
	}
}

// 去除尾部数据
func unPadding(origData []byte, tp aesPaddingType) []byte {
	switch tp {
	case PKCS7:
		return pkcs7UnPadding(origData)
	case Zero:
		return zeroUnPadding(origData)
	case ISO10126:
		return iso10126UnPadding(origData)
	case ISO9797M1:
		return iso9797m1UnPadding(origData)
	case ISO9797M2:
		return iso9797m2UnPadding(origData)
	case ANSIX923:
		return ansix923UnPadding(origData)
	case NoOrZero:
		return noUnPadding(origData, true)
	case No:
		return noUnPadding(origData, false)
	default:
		panic("padding type error")
	}
}

// zero
func zeroPadding(ciphertext []byte, blockSize int) []byte {
	paddingSize := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(0)}, paddingSize)
	return append(ciphertext, padText...)
}

func zeroUnPadding(origData []byte) []byte {
	length := len(origData)
	unPaddingSize := 0
	for i := length - 1; i >= 0; i-- {
		if origData[i] == byte(0) {
			unPaddingSize++
		} else {
			break
		}
	}
	return origData[:(length - unPaddingSize)]
}

// pkcs7
func pkcs7Padding(ciphertext []byte, blockSize int) []byte {
	paddingSize := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	return append(ciphertext, padText...)
}

func pkcs7UnPadding(origData []byte) []byte {
	length := len(origData)
	unPaddingSize := int(origData[length-1])
	return origData[:(length - unPaddingSize)]
}

// ISO10126
func iso10126Padding(ciphertext []byte, blockSize int) []byte {
	paddingSize := blockSize - len(ciphertext)%blockSize
	padText := make([]byte, paddingSize)
	for i := 0; i < paddingSize-1; i++ {
		padText[i] = byte(util.RandomInt64(0, 256))
	}
	padText[paddingSize-1] = byte(paddingSize)
	return append(ciphertext, padText...)
}

func iso10126UnPadding(origData []byte) []byte {
	length := len(origData)
	unPaddingSize := int(origData[length-1])
	return origData[:(length - unPaddingSize)]
}

// ISO9797M1
func iso9797m1Padding(ciphertext []byte, blockSize int) []byte {
	paddingSize := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(0)}, paddingSize)
	return append(ciphertext, padText...)
}

func iso9797m1UnPadding(origData []byte) []byte {
	length := len(origData)
	unPaddingSize := 0
	for i := length - 1; i >= 0; i-- {
		if origData[i] == byte(0) {
			unPaddingSize++
		} else {
			break
		}
	}
	return origData[:(length - unPaddingSize)]
}

// ISO9797M2
func iso9797m2Padding(ciphertext []byte, blockSize int) []byte {
	paddingSize := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(0)}, paddingSize)
	padText[0] = byte(0x80)
	return append(ciphertext, padText...)
}

func iso9797m2UnPadding(origData []byte) []byte {
	length := len(origData)
	unPaddingSize := 0
	for i := length - 1; i >= 0; i-- {
		if origData[i] == byte(0) {
			unPaddingSize++
		} else {
			break
		}
	}
	unPaddingSize++
	if origData[length-unPaddingSize] != byte(0x80) {
		panic("iso9797m2 data error")
	}
	return origData[:(length - unPaddingSize)]
}

// ANSIX923
func ansix923Padding(ciphertext []byte, blockSize int) []byte {
	paddingSize := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(0)}, paddingSize)
	padText[paddingSize-1] = byte(paddingSize)
	return append(ciphertext, padText...)
}

func ansix923UnPadding(origData []byte) []byte {
	length := len(origData)
	unPaddingSize := int(origData[length-1])
	return origData[:(length - unPaddingSize)]
}

// no
func noPadding(ciphertext []byte, blockSize int, zeroPadding bool) []byte {
	paddingSize := blockSize - len(ciphertext)%blockSize

	if paddingSize == blockSize || !zeroPadding {
		return ciphertext
	}

	padText := bytes.Repeat([]byte{byte(0)}, paddingSize)
	return append(ciphertext, padText...)
}

func noUnPadding(origData []byte, zeroPadding bool) []byte {
	length := len(origData)
	if !zeroPadding {
		return origData
	}

	unPaddingSize := 0
	for i := length - 1; i >= 0; i-- {
		if origData[i] == byte(0) {
			unPaddingSize++
		} else {
			break
		}
	}
	return origData[:(length - unPaddingSize)]
}
