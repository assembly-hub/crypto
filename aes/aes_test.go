package aes

import (
	"fmt"
	"testing"
)

// AesDemo aes demo
func TestAes(t *testing.T) {
	defer func() {
		if p := recover(); p != nil {
			t.Error()
		}
	}()

	aesKey := "poVVc2C9eUWNksde"
	aesObj := New(Conf{
		Key: aesKey,
		// IV: "", // default is key
		PaddingType: NoOrZero,
		// EncryptModel: CBC,
	})

	// 可以后续修改
	// aesObj.PaddingType(Zero)
	// aesObj.EncryptModel(OFB)

	// 加密
	d, err := aesObj.Encrypt("123")
	if err == nil {
		fmt.Println("data: ", d)
	} else {
		panic(err)
	}

	// 解密
	dd, err := aesObj.Decrypt(d)
	if err == nil {
		fmt.Println("data: ", dd)
	} else {
		panic(err)
	}
}
