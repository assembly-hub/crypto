// Package crypto
// md5、hash1、hash256、hash512签名
package crypto

import (
	"crypto"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"hash"
	"runtime"
)

func RsaSign(rsaPriKey string, data string, header bool) (r []byte, err error) {
	defer func() {
		if p := recover(); p != nil {
			r = nil
			err = fmt.Errorf("%v", p)
		}
	}()

	if !header {
		rsaPriKey = fmt.Sprintf("-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----", rsaPriKey)
	}
	block, _ := pem.Decode([]byte(rsaPriKey))
	priKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return nil, fmt.Errorf(file, line+1, err.Error())
	}
	// calculate hash value
	hashText := sha1.Sum([]byte(data))
	// Sign with hashText
	signText, err := rsa.SignPKCS1v15(rand.Reader, priKey, crypto.SHA1, hashText[:])
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return nil, fmt.Errorf(file, line+1, err.Error())
	}
	return signText, nil
}

func RsaVerify(rsaPubKey string, data string, signData []byte, header bool) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("%v", p)
		}
	}()

	if !header {
		rsaPubKey = fmt.Sprintf("-----BEGIN RSA PUBLIC KEY-----\n%s\n-----END RSA PUBLIC KEY-----", rsaPubKey)
	}
	block, _ := pem.Decode([]byte(rsaPubKey))
	// x509
	pubInter, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return fmt.Errorf(file, line+1, err.Error())
	}
	pubKey := pubInter.(*rsa.PublicKey)
	// hashText to verify
	hashText := sha1.Sum([]byte(data))
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA1, hashText[:], signData)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return fmt.Errorf(file, line+1, err.Error())
	}
	return nil
}

func RsaSignToBase64(rsaPriKey string, data string, header bool) (r string, err error) {
	sign, err := RsaSign(rsaPriKey, data, header)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sign), nil
}

func RsaVerifyForBase64(rsaPubKey string, data string, signData string, header bool) (err error) {
	s, err := base64.StdEncoding.DecodeString(signData)
	if err != nil {
		return err
	}

	err = RsaVerify(rsaPubKey, data, s, header)
	if err != nil {
		return err
	}
	return nil
}

// Md5Sign sign tool
func Md5Sign(original []byte) string {
	md5Obj := md5.New()
	md5Obj.Write(original)
	return hex.EncodeToString(md5Obj.Sum(nil))
}

// Hash256Sign sign tool
func Hash256Sign(original []byte) string {
	h := sha256.New()
	h.Write(original)
	return hex.EncodeToString(h.Sum(nil))
}

// Hash512Sign sign tool
func Hash512Sign(original []byte) string {
	h := sha512.New()
	h.Write(original)
	return hex.EncodeToString(h.Sum(nil))
}

// Hash1Sign sign tool
func Hash1Sign(original []byte) string {
	h := sha1.New()
	h.Write(original)
	return hex.EncodeToString(h.Sum(nil))
}

func HMacSign(key string, original string, f func() hash.Hash) string {
	h := hmac.New(f, []byte(key))
	h.Write([]byte(original))
	return hex.EncodeToString(h.Sum([]byte("")))
}
