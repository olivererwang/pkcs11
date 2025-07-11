package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
	"math/big"
)

var tokenLabel = "pk-rsa-key" // Replace with your desired token label

func findRSAKey(session p11.Session) (*p11.KeyPair, error) {
	pri, err := session.FindObject([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to find private key objects: %v", err)
	}
	pub, err := session.FindObject([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to find public key objects: %v", err)
	}
	return &p11.KeyPair{
		Private: p11.PrivateKey(pri),
		Public:  p11.PublicKey(pub),
	}, nil
}

func genRSA(session p11.Session) (*p11.KeyPair, error) {
	k, err := findRSAKey(session)
	if err == nil {
		fmt.Println("RSA key pair already exists.")
		return k, nil
	}
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	}
	// Example: Generate an RSA key pair (pseudo-code)
	keyPair, err := session.GenerateKeyPair(p11.GenerateKeyPairRequest{
		Mechanism:            *pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil),
		PublicKeyAttributes:  publicKeyTemplate,
		PrivateKeyAttributes: privateKeyTemplate,
	})
	if err != nil {
		panic(fmt.Sprintf("Failed to generate RSA key pair: %v", err))
	}

	return keyPair, nil
}
func testRSASign(keyPair p11.KeyPair) {
	message := []byte("Hello, RSA PKCS#11!")
	sig, err := keyPair.Private.Sign(*pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil), message)
	if err != nil {
		panic(fmt.Sprintf("Failed to sign message: %v", err))
	}
	fmt.Println("Signature:", sig)

	err = keyPair.Public.Verify(*pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil), message, sig)
	if err != nil {
		panic(fmt.Sprintf("Failed to verify signature: %v", err))
	} else {
		fmt.Println("Signature verified successfully.")
	}
}

func testRSAEncrypt(keyPair p11.KeyPair) {
	message := []byte("Hello, RSA PKCS#11!Hello, RSA PKCS#11!")
	oaepParams := pkcs11.NewOAEPParams(
		pkcs11.CKM_SHA_1,
		pkcs11.CKG_MGF1_SHA1,
		pkcs11.CKZ_DATA_SPECIFIED,
		nil,
	)
	ciphertext, err := keyPair.Public.Encrypt(*pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, oaepParams), message)
	if err != nil {
		panic(fmt.Sprintf("Failed to encrypt message: %v", err))
	}
	fmt.Printf("Ciphertext: %x\n", ciphertext)

	plaintext, err := keyPair.Private.Decrypt(*pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, nil), ciphertext)
	if err != nil {
		panic(fmt.Sprintf("Failed to decrypt ciphertext: %v", err))
	} else {
		fmt.Println("Decrypted plaintext:", string(plaintext))
	}
}

func getPEMPublicKey(keyPair p11.KeyPair) (string, error) {
	mod, err := p11.Object(keyPair.Public).Attribute(pkcs11.CKA_MODULUS)
	if err != nil {
		return "", fmt.Errorf("failed to get public key value: %v", err)
	}

	exp, err := p11.Object(keyPair.Public).Attribute(pkcs11.CKA_PUBLIC_EXPONENT)
	if err != nil {
		return "", fmt.Errorf("failed to get public exponent: %v", err)
	}

	modb := new(big.Int).SetBytes(mod)
	expb := new(big.Int).SetBytes(exp)

	rsaPub := rsa.PublicKey{
		N: modb,
		E: int(expb.Int64()), // 注意：必须是 int 类型
	}

	//derBytes := x509.MarshalPKCS1PublicKey(&rsaPub)
	derBytes, err := x509.MarshalPKIXPublicKey(&rsaPub)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %v", err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}
	return string(pem.EncodeToMemory(block)), nil
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
	keyPair, err := genRSA(session)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate RSA key pair: %v", err))
	}
	fmt.Println("Private Key:", keyPair.Private)
	fmt.Println("Public  Key:", keyPair.Public)
	fmt.Println("RSA key pair generated successfully.")
	testRSASign(*keyPair)
	testRSAEncrypt(*keyPair)
	pubKeyPEM, err := getPEMPublicKey(*keyPair)
	if err != nil {
		panic(fmt.Sprintf("Failed to get PEM public key: %v", err))
	}
	fmt.Println("PEM Public Key:\n", pubKeyPEM)
}
