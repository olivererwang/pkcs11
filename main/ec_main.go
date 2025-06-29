package main

import (
	"encoding/asn1"
	"fmt"
	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
)

func findEC(session p11.Session, label string) (*p11.KeyPair, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	pub, err := session.FindObject(template)
	if err != nil {
		return nil, fmt.Errorf("failed to find EC public key: %w", err)
	}
	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	priv, err := session.FindObject(privTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to find EC private key: %w", err)
	}
	return &p11.KeyPair{
		Public:  p11.PublicKey(pub),
		Private: p11.PrivateKey(priv),
	}, nil
}

func genEC(session p11.Session, tokenLabel string) (*p11.KeyPair, error) {

	keyPair, err := findEC(session, tokenLabel)
	if err == nil {
		fmt.Println("EC Key Pair already exists:", keyPair)
		return keyPair, nil
	} else {

		//ecParams := []byte{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A}
		secp256k1OID, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 10})
		fmt.Printf("Using OID for secp256k1: %x\n", secp256k1OID)

		publicKeyTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, secp256k1OID),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
		}
		privateKeyTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		}
		// Example: Generate an RSA key pair (pseudo-code)
		keyPair, err = session.GenerateKeyPair(p11.GenerateKeyPairRequest{
			Mechanism:            *pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil),
			PublicKeyAttributes:  publicKeyTemplate,
			PrivateKeyAttributes: privateKeyTemplate,
		})
		if err != nil {
			panic(fmt.Sprintf("Failed to generate EC key pair: %v", err))
		}
	}
	fmt.Println("Private Key:", keyPair.Private)
	fmt.Println("Public  Key:", keyPair.Public)
	return keyPair, nil
}

func getECPoint(session p11.Session, pub p11.PublicKey) error {
	ecPoint, err := p11.Object(pub).Attribute(pkcs11.CKA_EC_POINT)
	if err != nil {
		return fmt.Errorf("failed to get CKA_EC_POINT: %w", err)
	}
	fmt.Printf("EC Point (DER): %x\n", ecPoint)
	var ecPointBytes []byte
	_, err = asn1.Unmarshal(ecPoint, &ecPointBytes)
	if err != nil {
		panic(fmt.Sprintf("ASN.1 解包失败: %v", err))
	}
	fmt.Printf("EC Point (裸): %x\n", ecPointBytes)
	return nil
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
	keyPair, err := genEC(session, "ec-secp256k1-key") // Replace with your desired token label)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate EC key pair: %v", err))
	}
	fmt.Println("Found EC Key Pair:", keyPair)
	fmt.Println(getECPoint(session, keyPair.Public))
}
