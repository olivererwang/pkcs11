package main

import (
	"fmt"
	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
)

func genRSA(session p11.Session) {
	tokenLabel := "rsa-key" // Replace with your desired token label
	tokenPersistent := true
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
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
	fmt.Println("Private Key:", keyPair.Private)
	fmt.Println("Public  Key:", keyPair.Public)

	// Example: Sign a message (pseudo-code)
	message := []byte("Hello, RSA PKCS#11!")
	sig, err := keyPair.Private.Sign(*pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil), message)
	if err != nil {
		panic(fmt.Sprintf("Failed to sign message: %v", err))
	}
	fmt.Println("Signature:", sig)
	// Example: Verify the signature (pseudo-code)
	err = keyPair.Public.Verify(*pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil), message, sig)
	if err != nil {
		panic(fmt.Sprintf("Failed to verify signature: %v", err))
	} else {
		fmt.Println("Signature verified successfully.")
	}
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
	message := []byte("Hello, RSA PKCS#11!")
	ciphertext, err := keyPair.Public.Encrypt(*pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil), message)
	if err != nil {
		panic(fmt.Sprintf("Failed to encrypt message: %v", err))
	}
	fmt.Printf("Ciphertext: %x\n", ciphertext)

	plaintext, err := keyPair.Private.Decrypt(*pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil), ciphertext)
	if err != nil {
		panic(fmt.Sprintf("Failed to decrypt ciphertext: %v", err))
	} else {
		fmt.Println("Decrypted plaintext:", string(plaintext))
	}
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

	pri, err := session.FindObject([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	})
	if err != nil {
		panic(fmt.Sprintf("Failed to find private key objects: %v", err))
	}
	pub, err := session.FindObject([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	})
	if err != nil {
		panic(fmt.Sprintf("Failed to find private key objects: %v", err))
	}
	keyPair := p11.KeyPair{
		Private: p11.PrivateKey(pri),
		Public:  p11.PublicKey(pub),
	}
	testRSASign(keyPair)
	testRSAEncrypt(keyPair)
}
