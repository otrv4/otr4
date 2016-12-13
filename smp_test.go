package otr4

import (
	"encoding/hex"
	. "gopkg.in/check.v1"
)

type SMPSuite struct{}

var _ = Suite(&SMPSuite{})

func hexToByte(s string) []byte {
	bytes, _ := hex.DecodeString(s)
	return bytes
}

func (s *SMPSuite) Test_SMPSecretGeneration(c *C) {
	aliceFingerprint := hexToByte("0102030405060708090A0B0C0D0E0F101112" +
		"131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30" +
		"3132333435363738393A3B3C3D3E3F40")
	bobFingerprint := hexToByte("4142434445464748494A4B4C4D4E4F50515253" +
		"5455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F7071" +
		"72737475767778797A7B7C7D7E7F00")
	ssid := hexToByte("FFF3D1E407346468")
	secret := []byte("this is the user secret")

	rslt := generateSMPsecret(aliceFingerprint, bobFingerprint, ssid, secret)
	expctRslt := hexToByte("4784e640e6fd385a17d7908d3ef9b0eb1e8cab2d90c2" +
		"8874648d15d149f7019ff37e19b943b6c71944fc13c8f098bb41e39b648d" +
		"f6ba0388076504905f5a852a")

	c.Assert(rslt, DeepEquals, expctRslt)
}
