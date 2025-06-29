package main

import (
	"github.com/miekg/pkcs11"
	"log"
)

func main() {
	p := pkcs11.New("/usr/lib/softhsm/libsofthsm2.so")
	err := p.Initialize()
	if err != nil {
		log.Fatalf("Initialize failed: %v", err)
	}
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		log.Fatalf("GetSlotList failed: %v", err)
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		log.Fatalf("OpenSession failed: %v", err)
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, "1234") // CU PIN
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}
	defer p.Logout(session)

	// 你可以在这里添加其他操作，比如查找对象、签名等
	log.Println("Login successful")
}
