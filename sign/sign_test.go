package crypto

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestHash256Sign(t *testing.T) {
	key := "ljF388L6zsBncjLPYOlI0Y3R4D4fwLyr"
	data := "2"
	str := HMacSign(key, data, sha256.New)
	fmt.Println(str)
}

func TestPKCS1v15Sign(t *testing.T) {
	key := "MIICXQIBAAKBgQDPhVDR+fF7dGHUi2TlyddNhXvg4/NdSkmms7Dp5YPL/JaT9Kce\nRfCUttvzyw/tW+pUwxSBYj/g" +
		"gi+n1KcL1XXi2M7u8JaPpw18F1Fb9Q0zVri3Nab9\nIi1LhCeWX/wDvYUCKg2M6dDz14yj/aJPqafaqhSfdvOikJrURHh" +
		"21EvcvQIDAQAB\nAoGACE8OLVoUkRzXzerG32x1cmUl0JtP4yxWRpZrPvIxlLlITiQ9jLjAKTQpGlnH\nCXnkqAAnkgad" +
		"CCAuSEn7Zj3lulz0ui7keJCp7/i9dKw0O7TwXR5S4I3V4XY1qd51\n7M+IVOZnr67DYnZeD37JXDk37F2ZI52v9IXGnsZ" +
		"MB4WBcAECQQD2HJSHBr8Yo+tZ\nG5C/jc0MlqnMp8cBi39R/zI+mpTKOEP7Fw7iGF1xZDyijwmZXS0WIKXvk1wldmDR\n" +
		"NCSz7pwtAkEA19vNkkdIQB6Tmo8FlWjGLNublkQA/BoPswYKwJ7F1SO5n6+njBrP\nNCfU7oEHX3802BlR1qMucdwzwEL" +
		"5AEVM0QJBAOdacIkJ34PjO67VSdm4DASEcPQw\n19Ns9e/3zJyrJal/APC9eUEzFEwupQ1PFv/zZhnB8RroVJvmzxZ6RP" +
		"JcILUCQG7X\nss8bhXFPgjIKoS5gt+rO9i0KTIsoAsnGH31bynCxQJ9MPrgGCEJa9c9nOFcEZilV\njx2te6sCDRz8Bwr" +
		"pixECQQC0OV/pO0jXMGleBiYVaV1HQuAL2vBPEOdog6O0WoBr\nagUQGOykxZzOJdR1LXTiMdIiJYP4zY1hoDqJZ5dUMn" +
		"uW"
	data := "123"
	sign, err := RsaSign(key, data, false)
	if err != nil {
		panic(err)
	}

	k := "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDPhVDR+fF7dGHUi2TlyddNhXvg\n4/NdSkmms7Dp5YPL/JaT9KceRfCUtt" +
		"vzyw/tW+pUwxSBYj/ggi+n1KcL1XXi2M7u\n8JaPpw18F1Fb9Q0zVri3Nab9Ii1LhCeWX/wDvYUCKg2M6dDz14yj/aJPqafaq" +
		"hSf\ndvOikJrURHh21EvcvQIDAQAB"
	err = RsaVerify(k, data, sign, false)
	if err != nil {
		panic(err)
	}

	fmt.Println("ok")
}

func TestPKCS1v15Sign2(t *testing.T) {
	key := "MIICXgIBAAKBgQDeiK45T92yditn3ckvUq4bZsElEhl7k17hOx7/JWfhoV3vwNZHsXbpXdhqx1C2tnGrKmCHSb4xrF4h" +
		"KpJKnb+PrYjH7gtubJV9AkwmHIBP6m6Im/gQB+VePBOlnUg0H7zs6QC/EQeH4Jt62bga/8/EnZFUztU6D6Q5wh81wljpFwI" +
		"DAQABAoGBAMD+HsL7ndR5IXnJ4gIVnYOMIPPKd6kxjPaetGopAaevr+0O+4dfxDXtupQYWcqr/XapoN+Tt8wSpevzpL3rg0" +
		"Y00MXAJoeiMohnmvXRjmitmAS6DgUdAU1N5qCIRCSnJ4iYxfVyL5xLE5rhzBToZ/9rssC6YBiB88Lax0Oq4TCRAkEA9kv5h" +
		"kbAlH5F/26WE8O1Q417JjheH9nneVNkq+8AN6OyKhoPDeDyR9DnnClT02vQ4CaG0FwIReRsc0QD/MudLwJBAOdNC6g1EQoQ" +
		"Ibg7EzR3UiPlgXVbq+SxHVb7Q7oOttSpmKVejMWB2nvsyLdG46e6E3DyF7d51/ZiPAjbew2JiJkCQQDe31EkmNGbjch5o/B" +
		"aYjacsmJF66wA1oYH29a1XsirkI2gW4RT4sJbCkcLoLoiDuYsb7B+y0kRNeqNQ3b4QqgxAkEApyJpFfaihV76vqERU4wU8p" +
		"NYZHEFWI8S4FNXsQ4I1spl3rjfh6g5M+r5blXvErfGbIrC0HVetE5viwbtd+61oQJAS+j+U5qDdnOWr7U44EBACQa8Mr2e9" +
		"gT/ryh4YddJrqKpOQWkBukpkmfFUR1k0qMq6lGfMwGjYSXPVFhPZf0shw=="
	data := "appKey=MMU8JJ&dealId=2114339673&dealTitle=MaaS订单支付&deviceType=WEBAPP&nativeAppId=2386723" +
		"1&notifyUrl=https://rds-robox.baidu.com/operation/api/payment/payment_callback&returnUrl=111?or" +
		"der_no=lk07871652779438684420&timestamp=2022-06-22 10:45:53&totalAmount=1&tpOrderId=lk078716527" +
		"79438684420&tradeType=H5&userId=9989&userType=passId&version=V2"
	sign, err := RsaSignToBase64(key, data, false)
	if err != nil {
		panic(err)
	}

	fmt.Println(sign)

	k := "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDeiK45T92yditn3ckvUq4bZsElEhl7k17hOx7/JWfhoV3vwNZHsXbpXdhqx1" +
		"C2tnGrKmCHSb4xrF4hKpJKnb+PrYjH7gtubJV9AkwmHIBP6m6Im/gQB+VePBOlnUg0H7zs6QC/EQeH4Jt62bga/8/EnZFUztU6D" +
		"6Q5wh81wljpFwIDAQAB"
	err = RsaVerifyForBase64(k, data, sign, false)
	if err != nil {
		panic(err)
	}

	fmt.Println("ok")
}
