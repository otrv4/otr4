package otr4

import (
	"crypto/rand"

	"github.com/twstrike/ed448"

	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type OTR4Suite struct{}

var _ = Suite(&OTR4Suite{})

func (s *OTR4Suite) Test_Auth(c *C) {
	message := []byte("our message")
	out, err := auth(fixedRand(randAuthData), testPubA.h, testPubB.h, testPubC, testPrivA.z, message)

	c.Assert(out, DeepEquals, testSigma)
	c.Assert(err, IsNil)

	r := make([]byte, 270)
	out, err = auth(fixedRand(r), testPubA.h, testPubB.h, testPubC, testPrivA.z, message)

	c.Assert(err, ErrorMatches, ".*cannot source enough entropy")
	c.Assert(out, IsNil)

	r = make([]byte, 56)
	out, err = auth(fixedRand(r), testPubA.h, testPubB.h, testPubC, testPrivA.z, message)

	c.Assert(err, ErrorMatches, ".*cannot source enough entropy")
	c.Assert(out, IsNil)
}

func (s *OTR4Suite) Test_Verify(c *C) {
	message := []byte("our message")

	b := verify(testPubA.h, testPubB.h, testPubC, testSigma, message)

	c.Assert(b, Equals, true)
}

func (s *OTR4Suite) Test_VerifyAndAuth(c *C) {
	message := []byte("hello, I am a message")
	sigma, _ := auth(rand.Reader, testPubA.h, testPubB.h, testPubC, testPrivA.z, message)
	ver := verify(testPubA.h, testPubB.h, testPubC, sigma, message)
	c.Assert(ver, Equals, true)

	fakeMessage := []byte("fake message")
	ver = verify(testPubA.h, testPubB.h, testPubC, sigma, fakeMessage)
	c.Assert(ver, Equals, false)

	ver = verify(testPubB.h, testPubB.h, testPubC, sigma, message)
	c.Assert(ver, Equals, false)

	ver = verify(testPubA.h, testPubA.h, testPubC, sigma, message)
	c.Assert(ver, Equals, false)

	ver = verify(testPubA.h, testPubB.h, testPubB.h, sigma, message)
	c.Assert(ver, Equals, false)

	ver = verify(testPubA.h, testPubB.h, testPubC, testSigma, message)
	c.Assert(ver, Equals, false)
}

func (s *OTR4Suite) Test_DREnc(c *C) {
	m := new(drMessage)
	err := m.drEnc(testMessage, fixedRand(randDREData), testPubA, testPubB)
	c.Assert(m.cipher, DeepEquals, testDRMessage.cipher)
	c.Assert(m.proof, DeepEquals, testDRMessage.proof)
	c.Assert(err, IsNil)

	err = m.drEnc(testMessage, fixedRand(randDREData), invalidPub, testPubB)
	c.Assert(err, ErrorMatches, ".*not a valid public key")

	err = m.drEnc(testMessage, fixedRand([]byte{0x00}), testPubA, testPubB)
	c.Assert(err, ErrorMatches, ".*cannot source enough entropy")
}

func (s *OTR4Suite) Test_DRDec(c *C) {
	m, err := testDRMessage.drDec(testPubA, testPubB, testPrivA, 1)
	c.Assert(m, DeepEquals, testMessage)
	c.Assert(err, IsNil)

	m, err = testDRMessage.drDec(invalidPub, testPubB, testPrivA, 1)
	c.Assert(err, ErrorMatches, ".*not a valid public key")

	m, err = testDRMessage.drDec(testPubA, testPubB, testPrivB, 1)
	c.Assert(err, ErrorMatches, ".*cannot decrypt the message")

	m, err = testDRMessage.drDec(testPubA, testPubB, testPrivA, 2)
	c.Assert(err, ErrorMatches, ".*cannot decrypt the message")
}

func (s *OTR4Suite) Test_DREncryptAndDecrypt(c *C) {
	message := []byte{
		0xfd, 0xf1, 0x18, 0xbf, 0x8e, 0xc9, 0x64, 0xc7,
		0x94, 0x46, 0x49, 0xda, 0xcd, 0xac, 0x2c, 0xff,
		0x72, 0x5e, 0xb7, 0x61, 0x46, 0xf1, 0x93, 0xa6,
		0x70, 0x81, 0x64, 0x37, 0x7c, 0xec, 0x6c, 0xe5,
		0xc6, 0x8d, 0x8f, 0xa0, 0x43, 0x23, 0x45, 0x33,
		0x73, 0x79, 0xa6, 0x48, 0x57, 0xbb, 0x0f, 0x70,
		0x63, 0x8c, 0x62, 0x26, 0x9e, 0x17, 0x5d, 0x22,
	}

	priv1, pub1, err := deriveCramerShoupKeys(rand.Reader)
	priv2, pub2, err := deriveCramerShoupKeys(rand.Reader)

	drMessage := &drMessage{}
	err = drMessage.drEnc(message, rand.Reader, pub1, pub2)

	expMessage1, err := drMessage.drDec(pub1, pub2, priv1, 1)
	c.Assert(err, IsNil)
	c.Assert(expMessage1, DeepEquals, message)
	expMessage2, err := drMessage.drDec(pub1, pub2, priv2, 2)
	c.Assert(err, IsNil)
	c.Assert(expMessage2, DeepEquals, message)
}

func (s *OTR4Suite) Test_GenerationOfNIZKPK(c *C) {
	alpha1 := ed448.NewDecafScalar([]byte{
		0x1c, 0x51, 0x56, 0x90, 0x17, 0x2d, 0x14, 0x41,
		0x2c, 0x71, 0x8e, 0x1f, 0x1f, 0x2b, 0x38, 0x60,
		0x02, 0x23, 0x42, 0x97, 0xd4, 0x5c, 0x8b, 0x9d,
		0xb9, 0x67, 0xe9, 0x11, 0x9c, 0xe3, 0xbf, 0x14,
		0x99, 0xc2, 0xe1, 0xf3, 0xa1, 0x65, 0xb8, 0x30,
		0xbc, 0x97, 0x8b, 0xa9, 0x98, 0x86, 0x53, 0x6e,
		0x9f, 0x45, 0xbd, 0x44, 0x8a, 0x40, 0x2a, 0x12,
	})

	alpha2 := ed448.NewDecafScalar([]byte{
		0xeb, 0xb9, 0xdc, 0x1a, 0x38, 0x12, 0xed, 0xe1,
		0xbd, 0x4b, 0x2c, 0xfe, 0x12, 0x1f, 0xf8, 0x01,
		0xc9, 0x52, 0xa0, 0x69, 0xc1, 0x78, 0xa8, 0xd5,
		0xc5, 0xe1, 0x4f, 0x94, 0x01, 0x71, 0x55, 0xf6,
		0xce, 0x4b, 0xc7, 0xba, 0xe5, 0xcf, 0x02, 0xae,
		0xbd, 0xb5, 0x33, 0xd3, 0x5d, 0x5c, 0x2a, 0xf3,
		0xbf, 0xce, 0x5e, 0x4e, 0xc7, 0x4d, 0xa7, 0x3e,
	})

	k1 := ed448.NewDecafScalar([]byte{
		0xc9, 0x21, 0xa6, 0x41, 0xc3, 0x43, 0xb3, 0x4f,
		0x3e, 0x86, 0x99, 0xbf, 0x11, 0x75, 0x2c, 0x40,
		0x05, 0xb9, 0x0e, 0xd1, 0x01, 0xd8, 0x3e, 0xeb,
		0xda, 0xfa, 0x7e, 0x28, 0x94, 0xe8, 0x62, 0x31,
		0xa5, 0x62, 0xfd, 0x27, 0x85, 0x00, 0xdf, 0x4a,
		0xc3, 0xc2, 0x27, 0x2e, 0x11, 0x49, 0xfc, 0x3c,
		0xc0, 0xdf, 0x80, 0x3d, 0x7a, 0x2f, 0x1f, 0x06,
	})

	k2 := ed448.NewDecafScalar([]byte{
		0xc9, 0x21, 0xa6, 0x41, 0xc3, 0x43, 0xb3, 0x4f,
		0x3e, 0x86, 0x99, 0xbf, 0x11, 0x75, 0x2c, 0x40,
		0x5, 0xb9, 0xff, 0xd1, 0x1, 0xd8, 0x3e, 0xeb,
		0xda, 0xfa, 0x7e, 0x28, 0x20, 0xe8, 0x62, 0x31,
		0xa5, 0x34, 0xfd, 0x27, 0x85, 0x0, 0xdd, 0x4a,
		0xcc, 0xc2, 0x27, 0xee, 0x11, 0x10, 0xfc, 0x3c,
		0xc0, 0xdf, 0x80, 0x3d, 0x7a, 0x2f, 0x1f, 0x6,
	})

	p := nIZKProof{}
	err := p.genNIZKPK(fixedRand(randNIZKPKData), &testDRMessage.cipher, testPubA, testPubB, alpha1, alpha2, k1, k2)
	c.Assert(p, DeepEquals, testDRMessage.proof)
	c.Assert(err, IsNil)

	err = p.genNIZKPK(fixedRand([]byte{0x00}), &testDRMessage.cipher, testPubA, testPubB, alpha1, alpha2, k1, k2)
	c.Assert(err, ErrorMatches, "*.cannot source enough entropy")
}

func (s *OTR4Suite) Test_VerificationOfNIZKPK(c *C) {
	alpha1 := ed448.NewDecafScalar([]byte{
		0x1c, 0x51, 0x56, 0x90, 0x17, 0x2d, 0x14, 0x41,
		0x2c, 0x71, 0x8e, 0x1f, 0x1f, 0x2b, 0x38, 0x60,
		0x02, 0x23, 0x42, 0x97, 0xd4, 0x5c, 0x8b, 0x9d,
		0xb9, 0x67, 0xe9, 0x11, 0x9c, 0xe3, 0xbf, 0x14,
		0x99, 0xc2, 0xe1, 0xf3, 0xa1, 0x65, 0xb8, 0x30,
		0xbc, 0x97, 0x8b, 0xa9, 0x98, 0x86, 0x53, 0x6e,
		0x9f, 0x45, 0xbd, 0x44, 0x8a, 0x40, 0x2a, 0x12,
	})

	alpha2 := ed448.NewDecafScalar([]byte{
		0xeb, 0xb9, 0xdc, 0x1a, 0x38, 0x12, 0xed, 0xe1,
		0xbd, 0x4b, 0x2c, 0xfe, 0x12, 0x1f, 0xf8, 0x01,
		0xc9, 0x52, 0xa0, 0x69, 0xc1, 0x78, 0xa8, 0xd5,
		0xc5, 0xe1, 0x4f, 0x94, 0x01, 0x71, 0x55, 0xf6,
		0xce, 0x4b, 0xc7, 0xba, 0xe5, 0xcf, 0x02, 0xae,
		0xbd, 0xb5, 0x33, 0xd3, 0x5d, 0x5c, 0x2a, 0xf3,
		0xbf, 0xce, 0x5e, 0x4e, 0xc7, 0x4d, 0xa7, 0x3e,
	})

	valid, err := testDRMessage.proof.verifyNIZKPK(&testDRMessage.cipher, testPubA, testPubB, alpha1, alpha2)
	c.Assert(valid, Equals, true)
	c.Assert(err, IsNil)

	inValid, err := testDRMessage.proof.verifyNIZKPK(&testDRMessage.cipher, invalidPub, testPubB, alpha1, alpha2)
	c.Assert(inValid, Equals, false)
	c.Assert(err, ErrorMatches, ".*cannot decrypt the message")
}

func (s *OTR4Suite) Test_VerificationOfDRMessage(c *C) {
	alpha1 := ed448.NewDecafScalar([]byte{
		0x1c, 0x51, 0x56, 0x90, 0x17, 0x2d, 0x14, 0x41,
		0x2c, 0x71, 0x8e, 0x1f, 0x1f, 0x2b, 0x38, 0x60,
		0x02, 0x23, 0x42, 0x97, 0xd4, 0x5c, 0x8b, 0x9d,
		0xb9, 0x67, 0xe9, 0x11, 0x9c, 0xe3, 0xbf, 0x14,
		0x99, 0xc2, 0xe1, 0xf3, 0xa1, 0x65, 0xb8, 0x30,
		0xbc, 0x97, 0x8b, 0xa9, 0x98, 0x86, 0x53, 0x6e,
		0x9f, 0x45, 0xbd, 0x44, 0x8a, 0x40, 0x2a, 0x12,
	})

	valid, err := verifyDRMessage(testDRMessage.cipher.u11, testDRMessage.cipher.u21, testDRMessage.cipher.v1, alpha1, testPrivA)
	c.Assert(valid, Equals, true)
	c.Assert(err, IsNil)

	inValid, err := verifyDRMessage(testDRMessage.cipher.u22, testDRMessage.cipher.u21, testDRMessage.cipher.v1, alpha1, testPrivA)
	c.Assert(inValid, Equals, false)
	c.Assert(err, ErrorMatches, "*.cannot decrypt the message")
}
