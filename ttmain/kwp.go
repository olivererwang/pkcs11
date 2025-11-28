package main

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func main() {
	// 1. 读公钥
	f, _ := os.Open("/Users/timwang@bixin.com/yubikey_public.asc")
	defer f.Close()
	entList, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil {
		panic(err)
	}
	recipient := entList[0] // 第一个实体就是我们要的 RSA 加密子钥

	// 2. 加密
	plain := []byte("hello from pure Go")
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, "", nil)
	if err != nil {
		panic(err)
	}
	cipher, err := openpgp.Encrypt(w, []*openpgp.Entity{recipient}, nil, nil, nil)
	if err != nil {
		panic(err)
	}
	if _, err := io.WriteString(cipher, string(plain)); err != nil {
		panic(err)
	}
	cipher.Close()
	w.Close()

	fmt.Println("----- encrypted -----")
	fmt.Print(buf.String())
}
