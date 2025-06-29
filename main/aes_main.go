package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
)

var aesLabel = "pk-aes-key"

func findAESKey(session p11.Session) (*p11.SecretKey, error) {
	obj, err := session.FindObject([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, aesLabel),
	})
	if err != nil {
		return nil, fmt.Errorf("找不到AES密钥: %v", err)
	}
	k := p11.SecretKey(obj)
	return &k, nil
}

func genAES(session p11.Session) (*p11.SecretKey, error) {
	key, err := findAESKey(session)
	if err == nil {
		fmt.Println("AES密钥已存在。")
		return key, nil
	}
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, aesLabel),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32), // 256位
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	}
	secretKey, err := session.GenerateSecretKey(
		p11.GenerateSecretKeyRequest{
			Mechanism:     *pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil),
			KeyAttributes: template,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("生成AES密钥失败: %v", err)
	}
	return secretKey, nil
}

func testAESGCM(key *p11.SecretKey) {
	plaintext := []byte("Hello, AES-GCM PKCS#11!")
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)

	mech := pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, pkcs11.NewGCMParams(nonce, nil, 16*8))
	ciphertext, err := key.Encrypt(*mech, plaintext)
	if err != nil {
		panic(fmt.Sprintf("加密失败: %v", err))
	}
	fmt.Printf("密文(hex): %s\n", hex.EncodeToString(ciphertext))

	// 解密
	plaintext2, err := key.Decrypt(*mech, ciphertext)
	if err != nil {
		panic(fmt.Sprintf("解密失败: %v", err))
	}
	fmt.Printf("解密后明文: %s\n", string(plaintext2))
}

func main() {
	p, err := Initialize()
	if err != nil {
		panic(fmt.Sprintf("初始化PKCS#11模块失败: %v", err))
	}
	session, err := GetSession(p)
	if err != nil {
		defer p.Destroy()
		panic(fmt.Sprintf("获取session失败: %v", err))
	}
	defer finalize(p, session)
	key, err := genAES(session)
	if err != nil {
		panic(fmt.Sprintf("生成AES密钥失败: %v", err))
	}
	fmt.Println("AES密钥对象:", key)
	testAESGCM(key)
}
