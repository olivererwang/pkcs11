package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
)

func savePEMPublicKey(session p11.Session, pemData []byte, label string) (*p11.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER encoded public key: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not RSA public key")
	}
	modulus := rsaPub.N.Bytes()
	exponent := big.NewInt(int64(rsaPub.E)).Bytes()

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, exponent),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, modulus),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	pubKeyObj, err := session.CreateObject(publicKeyTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to create public key object: %v", err)
	}
	pubKey := p11.PublicKey(pubKeyObj)
	return &pubKey, nil
}

func getPEMPublicKey(key p11.PublicKey) (string, error) {
	mod, err := p11.Object(key).Attribute(pkcs11.CKA_MODULUS)
	if err != nil {
		return "", fmt.Errorf("failed to get public key value: %v", err)
	}

	exp, err := p11.Object(key).Attribute(pkcs11.CKA_PUBLIC_EXPONENT)
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

	filename := "./public_key.pem"
	filecontent, err := ioutil.ReadFile(filename)
	if err != nil && err != io.EOF {
		panic(fmt.Sprintf("Failed to read public key file: %v", err))
	}
	if len(filecontent) == 0 {
		panic("Public key file is empty")
	}
	pubKey, err := savePEMPublicKey(session, filecontent, "imported-rsa-key")
	if err != nil {
		panic(fmt.Sprintf("Failed to save PEM public key: %v", err))
	}
	fmt.Println("Imported Public Key Object:", *pubKey)
	pubKeyPEM, err := getPEMPublicKey(*pubKey)
	if err != nil {
		panic(fmt.Sprintf("Failed to get PEM public key: %v", err))
	}
	fmt.Println("PEM Public Key:\n", pubKeyPEM)
}
