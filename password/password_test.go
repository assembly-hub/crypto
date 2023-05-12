package crypto

import (
	"fmt"
	"testing"
)

func TestPassword(t *testing.T) {
	p := "123456"
	encode, err := PasswordEncode(p, "", 0)
	if err != nil {
		panic(err)
	}

	fmt.Println(encode)

	verify, err := PasswordVerify(p, encode)
	if err != nil {
		panic(err)
	}

	fmt.Println(verify)
}
