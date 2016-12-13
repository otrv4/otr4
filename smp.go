package otr4

import (
	"golang.org/x/crypto/sha3"
)

const smpVersion = 2

func generateSMPsecret(intrFingerprint, recvrFingerprint, ssid, secret []byte) []byte {
	h := sha3.New512()
	h.Write([]byte{smpVersion})
	h.Write(intrFingerprint)
	h.Write(recvrFingerprint)
	h.Write(ssid)
	h.Write(secret)
	return h.Sum(nil)
}
