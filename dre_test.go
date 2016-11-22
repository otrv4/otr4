package otr4

import (
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type DualRecieverEncryptionSuite struct{}

var _ = Suite(&DualRecieverEncryptionSuite{})

func (s *DualRecieverEncryptionSuite) Test_DualReceiverEncryption(c *C) {
	//pk1 := CramerShoup.PublicKey()
	//pk2 := CramerShoup.PublicKey()

	//m := "hi"

	//ct := DualRecieverEncryption.Encrypt(pk1, pk2, m)

	//expectedCiphertext := "bl"

	//c.Assert(ct, Equals, expectedCiphertext)
}
