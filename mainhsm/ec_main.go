package main

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"log"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/pkg/errors"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
)

// ecParams := []byte{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A}
var secp256k1OID, _ = asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 10})

func FindEC(session p11.Session, label string) (*p11.KeyPair, error) {
	//先找public key
	pub, err := findECPublicKey(session, label)
	if err != nil {
		return nil, errors.Wrap(err, "failed to find EC public key")
	} else if pub == nil {
		log.Printf("EC Public key with label '%s' not found in the session.", label)
		return nil, nil // Return nil if the public key is not found
	}

	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	priv, err := session.FindObject(privTemplate)
	if err != nil {
		if errors.Is(err, p11.ErrNoObjectsFound) {
			log.Printf("EC Private key with label '%s' not found in the session.", label)
			return nil, nil // Return nil if the private key is not found
		}
		return nil, errors.Wrap(err, "failed to find EC private key")
	}
	return &p11.KeyPair{
		Public:  p11.PublicKey(*pub),
		Private: p11.PrivateKey(priv),
	}, nil
}

func findECPublicKey(session p11.Session, label string) (*p11.Object, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	pub, err := session.FindObject(template)
	if err != nil {
		if errors.Is(err, p11.ErrNoObjectsFound) {
			return findECCertPublicKey(session, label)
		}
		return nil, errors.Wrap(err, "failed to find EC public key")
	}
	return &pub, nil
}
func findECCertPublicKey(session p11.Session, label string) (*p11.Object, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label+"--cert0"),
	}
	certObj, err := session.FindObject(template)
	if err != nil {
		if errors.Is(err, p11.ErrNoObjectsFound) {
			return nil, nil // Return nil if the public key is not found
		}
		return nil, errors.Wrap(err, "failed to find EC public key")
	}

	// 获取证书内容
	certBytes, err := certObj.Attribute(pkcs11.CKA_VALUE)
	if err != nil {
		return nil, fmt.Errorf("failed to get CKA_VALUE from certificate: %w", err)
	}
	var cert certificate
	_, err = asn1.Unmarshal(certBytes, &cert)
	if err != nil {
		log.Fatalf("asn1.Unmarshal certificate failed: %v", err)
	}

	// 从证书中提取公钥
	pubKeyBytes := cert.TBSCertificate.SubjectPublicKeyInfo.SubjectPublicKey.Bytes
	pubKey, err := secp256k1.ParsePubKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC public key from certificate: %w", err)
	}
	return saveECPubKey(session, pubKey, label)
}

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

type tbsCertificate struct {
	// ... skip other fields ...
	Raw                  asn1.RawContent
	Version              int `asn1:"optional,explicit,tag:0,default:0"`
	SerialNumber         asn1.RawValue
	Signature            pkix.AlgorithmIdentifier
	Issuer               asn1.RawValue
	Validity             asn1.RawValue
	Subject              asn1.RawValue
	SubjectPublicKeyInfo subjectPublicKeyInfo
	// ... skip extensions ...
}

type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

func saveECPubKey(session p11.Session, pubKey *secp256k1.PublicKey, label string) (*p11.Object, error) {

	// 1. 获取 ECPoint (04 || X || Y)
	ecPoint := pubKey.SerializeUncompressed()

	// 2. DER 编码为 OCTET STRING
	derECPoint, _ := asn1.Marshal(ecPoint)

	// 4. 创建 PKCS#11 公钥对象
	pubKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, secp256k1OID),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, derECPoint),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false), // 非永久
	}

	obj, err := session.CreateObject(pubKeyTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to create EC public key object: %w", err)
	}
	return &obj, nil
}

func genEC(session p11.Session, tokenLabel string) (*p11.KeyPair, error) {

	keyPair, err := FindEC(session, tokenLabel)
	if err != nil {
		return nil, fmt.Errorf("FindEC error: %w", err)
	}
	if keyPair != nil {
		fmt.Println("EC Key Pair is exists:", keyPair)
		return keyPair, nil
	} else {
		//fmt.Printf("Using OID for secp256k1: %x\n", secp256k1OID)

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
	fmt.Println(GetCompressPubkey(ecPointBytes))
	return nil
}

type ecdsaSignature struct {
	R, S *big.Int
}

func testECSign(keyPair p11.KeyPair) {
	message := []byte("Hello, EC PKCS#11!")
	hash := sha256.Sum256(message)
	mechanism := pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
	signature, err := keyPair.Private.Sign(*mechanism, hash[:])
	if err != nil {
		panic(fmt.Sprintf("Failed to sign message: %v", err))
	}
	fmt.Printf("Signature (R,S): %x\n", signature)
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	der, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
	if err != nil {
		panic(fmt.Sprintf("ASN.1 encoding failed: %v", err))
	}
	fmt.Printf("Signature (DER): %x\n", der)
	// Verify the signature
	err = keyPair.Public.Verify(*mechanism, hash[:], signature)
	if err != nil {
		panic(fmt.Sprintf("Signature verification failed: %v", err))
	}
	fmt.Println("Signature verified successfully.")
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
	//keyPair, err := FindEC(session, "HSM_DEFAULT_KEY")
	if err != nil {
		panic(fmt.Sprintf("Failed to generate EC key pair: %v", err))
	}
	fmt.Println("Found EC Key Pair:", keyPair)
	fmt.Println(getECPoint(session, keyPair.Public))
	testECSign(*keyPair)

}
