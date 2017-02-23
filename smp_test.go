package otr4

import (
	"encoding/hex"

	. "gopkg.in/check.v1"
)

func hexToBytes(s string) []byte {
	bytes, _ := hex.DecodeString(s)
	return bytes
}

func (s *OTR4Suite) Test_SMPSecretGeneration(c *C) {
	aliceFingerprint := hexToBytes("0102030405060708090A0B0C0D0E0F101112" +
		"131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30" +
		"3132333435363738393A3B3C3D3E3F40")
	bobFingerprint := hexToBytes("4142434445464748494A4B4C4D4E4F50515253" +
		"5455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F7071" +
		"72737475767778797A7B7C7D7E7F00")
	ssid := hexToBytes("FFF3D1E407346468")
	secret := []byte("user's secret")
	result := generateSMPsecret(aliceFingerprint, bobFingerprint, ssid, secret)

	expectedSMPSecret := hexToBytes("c57f90a829917526a94b8ed36f0eea8e676" +
		"190a07f6358682d358bc0471bcba401da479d59926ebd1fdfb371233e319dda35365" +
		"cc141ea5c61dd52dcc0cdcd21")

	c.Assert(result, DeepEquals, expectedSMPSecret)
}
