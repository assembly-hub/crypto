package aes

type aesPaddingType int

const (
	// Zero default
	Zero aesPaddingType = iota
	PKCS7
	ISO10126
	ISO9797M1
	ISO9797M2
	ANSIX923
	// NoOrZero 足位不追加0；不足位追加0
	NoOrZero
	// No 不追加，保留原始数据，如果数据不足报异常
	No
)

type aesEncryptModel int

const (
	// CBC default
	CBC aesEncryptModel = iota
	CTR
	OFB
	CFB
	ECB
)
