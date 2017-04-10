package otr4

import (
	"crypto/rand"

	. "gopkg.in/check.v1"
)

func (s *OTR4Suite) Test_GenerateAuthParams(c *C) {
	sigma := new(authMessage)

	r := make([]byte, 55)
	err := sigma.generateAuthParams(fixedRand(r))

	c.Assert(err, ErrorMatches, ".*cannot source enough entropy")

	r = make([]byte, 111)
	err = sigma.generateAuthParams(fixedRand(r))

	c.Assert(err, ErrorMatches, ".*cannot source enough entropy")

	r = make([]byte, 117)
	err = sigma.generateAuthParams(fixedRand(r))

	c.Assert(err, ErrorMatches, ".*cannot source enough entropy")
}

func (s *OTR4Suite) Test_Auth(c *C) {
	message := []byte("our message")
	sigma := new(authMessage)
	err := sigma.auth(fixedRand(randAuthData), testPubA.h, testPubB.h, testPubC, testPrivA.r, message)

	c.Assert(sigma, DeepEquals, testSigma)
	c.Assert(err, IsNil)

	r := make([]byte, 270)
	err = sigma.auth(fixedRand(r), testPubA.h, testPubB.h, testPubC, testPrivA.r, message)

	c.Assert(err, ErrorMatches, ".*cannot source enough entropy")

	r = make([]byte, 56)
	err = sigma.auth(fixedRand(r), testPubA.h, testPubB.h, testPubC, testPrivA.r, message)

	c.Assert(err, ErrorMatches, ".*cannot source enough entropy")
}

func (s *OTR4Suite) Test_Verify(c *C) {
	message := []byte("our message")

	b := testSigma.verify(testPubA.h, testPubB.h, testPubC, message)

	c.Assert(b, Equals, true)
}

// XXX: implement tests with the correct gen of keys
func (s *OTR4Suite) Test_VerifyAndAuth(c *C) {
	sigma := new(authMessage)
	message := []byte("hello, I am a message")
	fakeMessage := []byte("fake message")

	pubA, privA, _ := generateKeys(rand.Reader)
	pubB, _, _ := generateKeys(rand.Reader)

	err := sigma.auth(rand.Reader, pubA.h, pubB.h, testPubC, privA.r, message)
	ver := sigma.verify(pubA.h, pubB.h, testPubC, message)
	c.Assert(err, IsNil)
	c.Assert(ver, Equals, true)

	ver = sigma.verify(pubA.h, pubB.h, testPubC, fakeMessage)
	c.Assert(ver, Equals, false)

	ver = sigma.verify(pubB.h, pubB.h, testPubC, message)
	c.Assert(ver, Equals, false)

	ver = sigma.verify(pubA.h, pubA.h, testPubC, message)
	c.Assert(ver, Equals, false)

	ver = sigma.verify(pubA.h, pubB.h, pubB.h, message)
	c.Assert(ver, Equals, false)

	ver = testSigma.verify(pubA.h, pubB.h, testPubC, message)
	c.Assert(ver, Equals, false)
}
