package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const randomStr = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

func PasswordEncode(password string, salt string, iterations int) (string, error) {
	// 一共三个参数，分别是原始密码、盐、迭代次数

	// 如果没有设置盐，则使用12位的随机字符串
	if strings.TrimSpace(salt) == "" {
		salt = CreateRandomString(12)
	}

	// 确保盐不包含美元$符号
	if strings.Contains(salt, "$") {
		return "", errors.New("salt contains dollar sign ($)")
	}

	// 如果迭代次数小于等于0，则设置为180000
	if iterations <= 0 {
		iterations = 180000
	}

	// pbkdf2加密 <--- 关键
	hash := pbkdf2.Key([]byte(password), []byte(salt), iterations, sha256.Size, sha256.New)

	// base64编码成为固定长度的字符串
	buf := make([]byte, base64.StdEncoding.EncodedLen(len(hash)))
	base64.StdEncoding.Encode(buf, hash)

	// 最终字符串拼接成pbkdf2_sha256密钥格式
	var pw strings.Builder
	pw.Grow(13 + 3 + 6 + len(salt) + len(buf))

	pw.WriteString("pbkdf2_sha256")
	pw.WriteByte('$')
	pw.WriteString(strconv.FormatInt(int64(iterations), 10))
	pw.WriteByte('$')
	pw.WriteString(salt)
	pw.WriteByte('$')
	pw.Write(buf)
	return pw.String(), nil
}

// CreateRandomString 随机字符串生成函数
func CreateRandomString(len int) string {
	var container strings.Builder
	container.Grow(len)
	b := bytes.NewBufferString(randomStr)
	length := b.Len()
	bigInt := big.NewInt(int64(length))
	for i := 0; i < len; i++ {
		randomInt, _ := rand.Int(rand.Reader, bigInt)
		container.WriteByte(randomStr[randomInt.Int64()])
	}
	return container.String()
}

func PasswordVerify(password string, encoded string) (bool, error) {
	// 输入两个参数，分别是原始密码、需要校验的密钥（数据库中存储的密码）
	// 输出校验结果（布尔值）、错误

	// 先根据美元$符号分割密钥为4个子字符串
	s := strings.Split(encoded, "$")

	// 如果分割结果不是4个子字符串，则认为不是pbkdf2_sha256算法的结果密钥，跳出错误
	if len(s) != 4 {
		return false, errors.New("hashed password components mismatch")
	}

	// 分割子字符串的结果分别为算法名、迭代次数、盐和base64编码
	// ---> 这里可以获得加密用的盐
	algorithm, iterations, salt := s[0], s[1], s[2]

	// 如果密钥算法名不是pbkdf2_sha256算法，跳出错误
	if algorithm != "pbkdf2_sha256" {
		return false, errors.New("algorithm mismatch")
	}

	// 将迭代次数转换成int数据类型 -->这里可以获得加密用的迭代次数
	i, err := strconv.Atoi(iterations)
	if err != nil {
		return false, errors.New("unreadable component in hashed password")
	}

	// 将原始密码用上面获取的盐、迭代次数进行加密
	newEncoded, err := PasswordEncode(password, salt, i)
	if err != nil {
		return false, err
	}

	// 最终用hmac.Equal函数判断两个密钥是否相同
	return hmac.Equal([]byte(newEncoded), []byte(encoded)), nil
}
