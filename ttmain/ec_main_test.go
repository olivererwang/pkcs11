package ttmain

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"log"
	"testing"

	"crypto/x509/pkix"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

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

func TestParse(t *testing.T) {
	certHex := "3082014c3081f2a003020100020202e1300b06072a8648ce3d04010500302e310b300906035504061302484b310f300d0603550407130643656e747265310e300c060355040313054e657742583022180f32303235313031323032343935315a180f38393934303831373037313235355a302e310b300906035504061302484b310f300d0603550407130643656e747265310e300c060355040313054e657742583056301006072a8648ce3d020106052b8104000a034200048fe29031096d5f85af1e12b733b6fb5a6843fd7fc67ddc4f5ec8b3851c1d2e4b05e31433050e49cf075aec98c4e9a843cc4c7a6a26a2590918426d003fd6df12300b06072a8648ce3d040105000348003045022100e517a9958edbd98cc2753cf149e71152c85bfed77c5a2a1af09cb58cabb3af3a022049bcfbb74f53912a10022720aebc6975f85c898d3656a0dc9b3c17884cb61fca"
	certBytes, _ := hex.DecodeString(certHex)

	var cert certificate
	_, err := asn1.Unmarshal(certBytes, &cert)
	if err != nil {
		log.Fatalf("asn1.Unmarshal certificate failed: %v", err)
	}

	pubKeyBytes := cert.TBSCertificate.SubjectPublicKeyInfo.SubjectPublicKey.Bytes
	pubKey, err := secp256k1.ParsePubKey(pubKeyBytes)
	if err != nil {
		log.Fatalf("ParsePubKey failed: %v", err)
	}
	fmt.Printf("secp256k1 pubkey: %x\n", pubKey.SerializeCompressed())
}
