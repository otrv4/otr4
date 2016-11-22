package otr4

import . "gopkg.in/check.v1"

type CramerShoupGenerateKeysSuite struct{}

var _ = Suite(&CramerShoupGenerateKeysSuite{})

func (s *CramerShoupGenerateKeysSuite) Test_CramerShoupSecretKeyGeneration(c *C) {
	secretKey, ok := generateSecretKey()
	c.Assert(ok, Equals, true)
	c.Assert(secretKey, NotNil)
}

func (s *CramerShoupGenerateKeysSuite) Test_CramerShoupPublicKeyGeneration(c *C) {
	publicKey, ok := generatePublicKey()
	c.Assert(ok, Equals, true)
	c.Assert(publicKey, NotNil)
}
