package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/miekg/pkcs11"
	"math/big"
	"time"
)

func saveCert(p *pkcs11.Ctx, session pkcs11.SessionHandle, pubKeyHandle pkcs11.ObjectHandle, hsmPrivateKeySigner crypto.Signer) {
	// 1. 从 HSM 获取公钥参数
	attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}
	values, _ := p.GetAttributeValue(session, pubKeyHandle, attrs)
	modulus := values[0].Value
	exponent := values[1].Value

	// 2. 构造 Go 的 rsa.PublicKey
	n := new(big.Int).SetBytes(modulus)
	e := int(new(big.Int).SetBytes(exponent).Int64())
	pub := &rsa.PublicKey{N: n, E: e}

	// 3. 生成自签名证书模板
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "SelfSigned"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:         true,
	}

	// 4. 用 HSM 私钥做签名（需实现 crypto.Signer 接口的包装器）
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, hsmPrivateKeySigner)
	if err != nil {
		// 处理错误
		return
	}
	// 5. 以数据对象形式存入 HSM
	certAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "SelfSignedCert"),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, certDER),
	}
	_, err = p.CreateObject(session, certAttrs)

}
func getCert(p *pkcs11.Ctx, session pkcs11.SessionHandle) (*rsa.PublicKey, error) {
	// 6. 查询并取出证书
	findAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "SelfSignedCert"),
	}
	_ = p.FindObjectsInit(session, findAttrs)
	objs, _, _ := p.FindObjects(session, 1)
	_ = p.FindObjectsFinal(session)
	certAttrsOut := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)}
	certVal, _ := p.GetAttributeValue(session, objs[0], certAttrsOut)
	certDER := certVal[0].Value
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, x509.IncorrectPasswordError // 或自定义错误
	}
	return pub, nil
}
