package otr4

import (
	"github.com/twstrike/ed448"

	. "gopkg.in/check.v1"
)

func (s *OTR4Suite) Test_IsValidPubKey(c *C) {
	ok := isValidPublicKey(testPubA)

	c.Assert(ok, Equals, true)

	ok = isValidPublicKey(invalidPub)

	c.Assert(ok, Equals, false)
}

func (s *OTR4Suite) Test_GenerateKeys(c *C) {
	expPub := []byte{
		0x5c, 0x23, 0x5f, 0xab, 0x15, 0xd7, 0x86, 0x98,
		0xd6, 0xf4, 0x12, 0xef, 0xdc, 0x08, 0xfc, 0xf0,
		0xf6, 0x78, 0xea, 0x95, 0x85, 0xbc, 0x60, 0xb0,
		0x3d, 0xdc, 0x87, 0x58, 0x7a, 0x4e, 0xcf, 0x30,
		0x54, 0x75, 0x4c, 0x1b, 0x21, 0x84, 0x69, 0x92,
		0x5e, 0x43, 0xea, 0x53, 0x3f, 0x62, 0x10, 0x6a,
		0x80, 0xb4, 0x28, 0xd3, 0xb5, 0xf5, 0x11, 0xd4,
		0x80,
	}

	privBytes := []byte{
		0x2c, 0xeb, 0x0d, 0x7d, 0xcf, 0x29, 0x18, 0x72,
		0x62, 0x1c, 0x47, 0xcb, 0x95, 0xd5, 0xf4, 0x3f,
		0x5c, 0xd3, 0x9a, 0x65, 0xd4, 0x93, 0x0b, 0x58,
		0xd4, 0x86, 0x49, 0x23, 0xa9, 0x74, 0xbe, 0xaf,
		0x8d, 0xc2, 0xbe, 0xb2, 0xef, 0x36, 0x29, 0x77,
		0x5d, 0x97, 0x9e, 0x7f, 0xb7, 0xb2, 0x20, 0xfe,
		0x03, 0x0f, 0x46, 0x90, 0x0d, 0xac, 0xd5, 0x83,
		0x00,
	}

	expPriv := ed448.NewScalar(privBytes)
	// Since the cofactor will be multiplied during
	// encoding, divide by it here.
	expPriv.Halve(expPriv)
	expPriv.Halve(expPriv)

	random := []byte{
		0xad, 0xd0, 0x35, 0x07, 0x1d, 0x09, 0x6c, 0xd3,
		0xdd, 0xf8, 0x96, 0x59, 0x39, 0x1c, 0x29, 0xa2,
		0x1e, 0x49, 0x34, 0xae, 0xc1, 0x79, 0x0e, 0x85,
		0x1c, 0x06, 0x73, 0xf2, 0xdd, 0x5d, 0x39, 0x71,
		0xf5, 0x70, 0x71, 0x4d, 0x5c, 0xca, 0x18, 0x02,
		0xaf, 0xa3, 0x85, 0x1b, 0x8a, 0x53, 0x39, 0xb7,
		0xa2, 0x33, 0x1b, 0x8a, 0x53, 0x39, 0xb7, 0xa2,
		0xb7,
	}

	public, priv, err := generateKeys(fixedRand(random))
	pub := public.h.DSAEncode()

	c.Assert(priv.r, DeepEquals, expPriv)
	c.Assert(pub, DeepEquals, expPub)
	c.Assert(err, IsNil)
}

func (s *OTR4Suite) Test_SerializeLongTermPubKey(c *C) {
	ser := testPubA.serialize()

	c.Assert(ser, DeepEquals, serPubA)
	c.Assert(ser, HasLen, 58)

	testPub := &publicKey{}
	var exp []byte

	ser = testPub.serialize()

	c.Assert(ser, DeepEquals, exp)
}

func (s *OTR4Suite) Test_DeserializeLongTermPubKey(c *C) {
	pub, err := deserialize(serPubA)

	c.Assert(pub.h.Equals(testPubA.h), DeepEquals, true)
	c.Assert(err, IsNil)

	ser := []byte{0x00}
	pub, err = deserialize(ser)

	c.Assert(err, ErrorMatches, "*. invalid length")
}
