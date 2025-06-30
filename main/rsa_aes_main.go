package main

import (
	"fmt"
	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
)

// 先生成AES key，并使用AES key加密
// 然后使用RSA公钥wrap AES key
// 最后，把AES密文和RSA密文存储到一个字符串中
// len(EncryptedAESKey) + RSA_OAEP_encrypt(AesKey) + AES_Ciphertext
// AES_Ciphertext = AES_GCM_encrypt(AesKey, plaintext) + IV

func findRSAPubKey(session p11.Session, label string) (*p11.PublicKey, error) {
	pub, err := session.FindObject([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to find public key objects: %v", err)
	}
	p := p11.PublicKey(pub)
	return &p, nil
}

func newTempAESKey(session p11.Session) (*p11.SecretKey, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
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

func encryptAESGCM(key p11.SecretKey, plaintext []byte) ([]byte, error) {

	gcmParams := pkcs11.NewGCMParams(make([]byte, 12), nil, 128)
	mech := pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gcmParams)
	ciphertext, err := key.Encrypt(*mech, plaintext)
	if err != nil {
		panic(fmt.Sprintf("加密失败: %v", err))
	}
	nonce := gcmParams.IV()
	// Prepend nonce to ciphertext
	ciphertextWithNonce := make([]byte, len(nonce)+len(ciphertext))
	copy(ciphertextWithNonce[:len(nonce)], nonce)
	copy(ciphertextWithNonce[len(nonce):], ciphertext)
	gcmParams.Free()
	return ciphertextWithNonce, nil
}

func decryptAESGCM(key p11.SecretKey, ciphertext []byte) ([]byte, error) {
	// Extract nonce from the beginning of the ciphertext
	if len(ciphertext) < 12 {
		return nil, fmt.Errorf("密文长度不足，无法提取nonce")
	}
	nonce := ciphertext[:12]
	ciphertext = ciphertext[12:]
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("密文内容为空")
	}
	mech := pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, pkcs11.NewGCMParams(nonce, nil, 16*8))
	plaintext, err := key.Decrypt(*mech, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("解密失败: %v", err)
	}
	return plaintext, nil
}

func wrapAESKey(session p11.Session, aesKey p11.SecretKey, pubKey p11.PublicKey) ([]byte, error) {
	// Wrap AES key with RSA public key
	oaepParams := pkcs11.NewOAEPParams(
		pkcs11.CKM_SHA_1,
		pkcs11.CKG_MGF1_SHA1,
		pkcs11.CKZ_DATA_SPECIFIED,
		nil,
	)

	mech := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, oaepParams)
	wrappedKey, err := session.WrapKey(mech, p11.Object(pubKey), p11.Object(aesKey))
	if err != nil {
		return nil, fmt.Errorf("wrap AES key failed: %v", err)
	}
	//wrappedKey, err := pubKey.Encrypt(*mech, []byte("my data"))
	if err != nil {
		return nil, fmt.Errorf("wrap AES key failed: %v", err)
	}

	return wrappedKey, nil
}

func main() {
	p, err := Initialize()
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize PKCS#11 module: %v", err))
	}
	session, err := GetSession(p)
	if err != nil {
		defer p.Destroy()
		panic(fmt.Sprintf("Failed to get session: %v", err))
	}
	defer finalize(p, session)
	rsaPublicKey, err := findRSAPubKey(session, "openssl-rsa-pubkey")
	if err != nil {
		panic(fmt.Sprintf("Failed to find RSA public key: %v", err))
	}
	aesKey, err := newTempAESKey(session)
	if err != nil {
		panic(fmt.Sprintf("Failed to find AES key: %v", err))
	}
	wrappedKey, err := wrapAESKey(session, *aesKey, *rsaPublicKey)
	if err != nil {
		panic(fmt.Sprintf("Failed to wrap AES key: %v", err))
	}
	plaintext := []byte("Hello, Tim~~!")
	ciphertext, err := encryptAESGCM(*aesKey, plaintext)
	if err != nil {
		panic(fmt.Sprintf("Failed to encrypt plaintext: %v", err))
	}
	fmt.Printf("Wrapped AES Key: %x\n", wrappedKey)
	fmt.Printf("Ciphertext: %x\n", ciphertext)
	result := make([]byte, 0, 2+len(wrappedKey)+len(ciphertext))
	result = append(result, byte(len(wrappedKey)>>8), byte(len(wrappedKey)))
	result = append(result, wrappedKey...)
	result = append(result, ciphertext...)
	fmt.Printf("Final Result: %x\n", result)
}
