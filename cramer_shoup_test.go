package otr4

import (
	. "gopkg.in/check.v1"
)

func (s *OTR4Suite) Test_IsValidPubKey(c *C) {
	ok := isValidPublicKey(testPubA)

	c.Assert(ok, Equals, true)

	ok = isValidPublicKey(invalidPub)

	c.Assert(ok, Equals, false)
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
