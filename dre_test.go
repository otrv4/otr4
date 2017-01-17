package otr4

import (
	"github.com/twstrike/ed448"
	"math/big"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type DualReceiverEncryptionSuite struct{}

var _ = Suite(&DualReceiverEncryptionSuite{})

func (s *DualReceiverEncryptionSuite) Test_DualReceiverEncryption(c *C) {
	//pk1 := CramerShoup.PublicKey()
	//pk2 := CramerShoup.PublicKey()

	//m := "hi"

	//ct := DualRecieverEncryption.Encrypt(pk1, pk2, m)

	//expectedCiphertext := "bl"

	//c.Assert(ct, Equals, expectedCiphertext)
}

//TODO Finish test, update publickey and secretkey type to use type in Ed448
func (s *DualReceiverEncryptionSuite) Test_Auth(c *C) {
	pubKey := &publicKey{
		big.NewInt(0),
	}
	secKey := &secretKey{
		big.NewInt(1),
	}
	message := []byte{0, 1, 0, 0, 0}
	sigma := auth(pubKey, pubKey, pubKey, secKey, message)

	c.Assert(sigma, HasLen, 6)
	c.Assert(sigma[0], FitsTypeOf, ed448.BigNumber{})
	c.Assert(sigma[1], FitsTypeOf, ed448.BigNumber{})
	c.Assert(sigma[2], FitsTypeOf, ed448.BigNumber{})
	c.Assert(sigma[3], FitsTypeOf, ed448.BigNumber{})
	c.Assert(sigma[4], FitsTypeOf, ed448.BigNumber{})
	c.Assert(sigma[5], FitsTypeOf, ed448.BigNumber{})
}

func (s *DualReceiverEncryptionSuite) Test_HashToScalar(c *C) {
	d := []byte{1, 2, 1, 1, 1}
	out := hashToScalar(d)
	exp := ed448.BigNumber{
		0x998b42ad, 0xd088f153, 0x91d0735, 0xf8ddd36c,
		0x1c395996, 0x491ea229, 0x79c1ae34, 0x61c850e,
		0x5dddf273, 0x70f57139, 0xca5c4d71, 0xa3af0218,
		0x538a1b85, 0x33a2b739, 0x0, 0x0,
	}

	c.Assert(out, FitsTypeOf, ed448.BigNumber{})
	c.Assert(out, Equals, exp)
}
