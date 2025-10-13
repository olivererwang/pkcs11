package main

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
	"github.com/pkg/errors"
)

func FindMasterKey(session p11.Session, label string) (*p11.KeyPair, error) {
	pubtemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	pub, err := session.FindObject(pubtemplate)
	if err != nil {
		if errors.Is(err, p11.ErrNoObjectsFound) {
			log.Printf("Master key(pub) with label '%s' not found in the session.", label)
			return nil, nil
		}
		return nil, errors.Wrap(err, "failed to find EC public key")
	}
	// Find the master key object in the specified slot
	pritemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_BIP32),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	object, err := session.FindObject(pritemplate)
	if err != nil {
		if errors.Is(err, p11.ErrNoObjectsFound) {
			log.Printf("Master key(priv) with label '%s' not found in the session.", label)
			return nil, nil // Return nil if the master key is not found
		}
		return nil, fmt.Errorf("FindMasterKey: %v", err)
	}
	//return &p, nil
	return &p11.KeyPair{
		Public:  p11.PublicKey(pub),
		Private: p11.PrivateKey(object),
	}, nil
}

func genGenericKey(session p11.Session, label string, length int) (*p11.SecretKey, error) {
	// Define the template for the key
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, length),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	// Generate the key
	secretKey, err := session.GenerateSecretKey(
		p11.GenerateSecretKeyRequest{
			Mechanism:     *pkcs11.NewMechanism(pkcs11.CKM_GENERIC_SECRET_KEY_GEN, nil),
			KeyAttributes: template,
		})
	if err != nil {
		return nil, fmt.Errorf("genGenericKey: %v", err)
	}
	return secretKey, nil
}

func GetExtendECPoint(pub p11.PublicKey) ([]byte, error) {
	ecPoint, err := p11.Object(pub).Attribute(pkcs11.CKA_EC_POINT)
	if err != nil {
		return nil, fmt.Errorf("failed to get CKA_EC_POINT: %w", err)
	}
	var ecPointBytes []byte
	_, err = asn1.Unmarshal(ecPoint, &ecPointBytes)
	if err != nil {
		return nil, fmt.Errorf("ASN.1 decoding failed: %w", err)
	}
	return ecPointBytes, nil
}

func GenMasterKey(session p11.Session, label string) (*p11.KeyPair, error) {
	// Check if the master key already exists
	key, err := FindMasterKey(session, label)
	if err != nil {
		return nil, fmt.Errorf("GenMasterKey: failed to find master key: %v", err)
	}
	if key != nil {
		//log.Printf("Master key with label '%s' already exists.", label)
		return key, nil // Return the existing master key if found
	}

	seed, err := genGenericKey(session, label+"_seed", 16)
	if err != nil {
		return nil, fmt.Errorf("GenMasterKey: failed to generate random seed: %v", err)
	}

	// Generate the master key
	masterKey, err := session.GenerateBIP32MasterKeyPair(*seed, label)
	if err != nil {
		return nil, fmt.Errorf("GenMasterKey: %v", err)
	}
	return masterKey, nil
}

func DeriveChildKey(session p11.Session, masterKey *p11.PrivateKey, path []uint32) (*p11.KeyPair, error) {
	if masterKey == nil {
		return nil, fmt.Errorf("DeriveChildKey: master key is nil")
	}
	// Derive the child key using the master key and the parsed path
	childKey, err := session.DeriveChildKeyPair(*masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("DeriveChildKey: %v", err)
	}
	return childKey, nil
}

func parsePath(path string) []uint32 {
	path = strings.Replace(path, "m/", "", 1)
	split := strings.Split(path, "/")
	pathUints := make([]uint32, len(split))
	for i, index := range split {
		var x uint32
		if index[len(index)-1] == '\'' {
			x = 0x80000000
			index = strings.TrimRight(index, "'")
		}
		x1, _ := strconv.ParseUint(index, 10, 32)
		x += uint32(x1)
		pathUints[i] = x
	}
	return pathUints
}

func injectSeed(session p11.Session, seed []byte) (*p11.SecretKey, error) {
	aesTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
	}
	wrappingKey, err := session.GenerateSecretKey(
		p11.GenerateSecretKeyRequest{
			Mechanism:     *pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil),
			KeyAttributes: aesTemplate,
		})
	if err != nil {
		return nil, err
	}

	mech := pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	encrypted, err := wrappingKey.Encrypt(*mech, seed)

	if err != nil {
		return nil, err
	}

	seedTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, len(seed)),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "bip32_seed"),
	}
	k, err := session.UnwrapKey(mech, p11.Object(*wrappingKey), encrypted, seedTemplate)
	if err != nil {
		return nil, err
	}
	r := p11.SecretKey(*k)
	return &r, nil
}

func testInject(session p11.Session) {
	//v := []string{"000102030405060708090a0b0c0d0e0f", "m/0'", "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"}
	v := []string{"000102030405060708090a0b0c0d0e0f", "m/0'/1/2'", "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2"}
	path := parsePath(v[1])
	fmt.Printf("path: %x\n", path)
	seed, _ := hex.DecodeString(v[0])
	seedKey, err := injectSeed(session, seed)
	if err != nil {
		log.Fatalf("injectSeed error: %v", err)
	}
	//seedKey, err := genGenericKey(session, "test_inject_seed", 16) // 生成一个随机key，避免覆盖
	//if err != nil {
	//	log.Fatalf("genGenericKey error: %v", err)
	//}
	masterKey, err := session.GenerateBIP32MasterKeyPair(*seedKey, "test_inject")
	if err != nil {
		log.Fatalf("GenerateBIP32MasterKeyPair error: %v", err)
	}
	fmt.Printf("childKey: %v\n", masterKey)
	mecPoint, err := GetExtendECPoint(p11.PublicKey(masterKey.Public))
	fmt.Printf("mecPoint: %x\n", mecPoint)
	childKey, err := DeriveChildKey(session, &masterKey.Private, path)
	if err != nil {
		log.Fatalf("DeriveChildKey error: %v", err)
	}
	fmt.Printf("childKey: %v\n", childKey)
	ecPoint, err := GetExtendECPoint(p11.PublicKey(childKey.Public))
	if err != nil {
		log.Fatalf("GetExtendECPoint error: %v", err)
	}
	compressPubkey, _ := GetCompressPubkey(ecPoint)
	fmt.Printf("ecPoint: %x\n", ecPoint)
	fmt.Printf("pubkey(b): %x\n", compressPubkey)
	fmt.Println("pubkey(v):", v[2])
	extendKey, err := childKey.Public.ExportBIP32PubKey()
	if err != nil {
		log.Fatalf("ExportBIP32PubKey error: %v", err)
	}
	fmt.Printf("extend pubkey: %s\n", string(extendKey))
}

func testDervieChild(session p11.Session) {
	masterKey, err := FindMasterKey(session, "client_deposit")
	if err != nil {
		log.Fatalf("FindMasterKey error: %v", err)
	}
	if masterKey == nil {
		log.Fatalf("masterKey is nil")
	}
	path := parsePath("m/0'/1/2'")
	childKey, err := DeriveChildKey(session, &masterKey.Private, path)
	if err != nil {
		log.Fatalf("DeriveChildKey error: %v", err)
	}
	ecPoint, err := GetExtendECPoint(p11.PublicKey(childKey.Public))
	if err != nil {
		log.Fatalf("GetExtendECPoint error: %v", err)
	}
	fmt.Printf("ecPoint: %x\n", ecPoint)
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
	testInject(session)
	//master, err := GenMasterKey(session, "test_masterkey")
	//if err != nil {
	//	panic(fmt.Sprintf("GenMasterKey error: %v", err))
	//}
	//fmt.Printf("master key: %x\n", getBIPECPoint(session, master.Public))
}
