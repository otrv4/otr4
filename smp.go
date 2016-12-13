package otr4

import (
	"golang.org/x/crypto/sha3"
)

const smpVersion = 1

func generateSMPsecret(initiatorFingerprint, receiverFingerprint, ssid, secret []byte) []byte {
	h := sha3.New512()
	h.Write([]byte{smpVersion})
	h.Write(initiatorFingerprint)
	h.Write(receiverFingerprint)
	h.Write(ssid)
	h.Write(secret)
	return h.Sum(nil)
}
