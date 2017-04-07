package otr4

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/twstrike/ed448"
)

func (c *conversation) rand() io.Reader {
	if c.random != nil {
		return c.random
	}
	return rand.Reader
}

func randSymKey(rand io.Reader) ([]byte, error) {
	var b [symKeyBytes]byte

	_, err := io.ReadFull(rand, b[:])
	if err != nil {
		return nil, notEnoughEntropy
	}

	return b[:], nil
}

func randScalar(rand io.Reader) (ed448.Scalar, error) {
	var b [fieldBytes]byte

	_, err := io.ReadFull(rand, b[:])
	if err != nil {
		return nil, notEnoughEntropy
	}

	return ed448.NewScalar(b[:]), nil
}

func randLongTermScalar(rand io.Reader) (ed448.Scalar, error) {
	var b [fieldBytes]byte
	var out [fieldBytes]byte

	_, err := io.ReadFull(rand, b[:])
	if err != nil {
		return nil, notEnoughEntropy
	}

	hash := sha3.NewShake256()
	hash.Write(b[:])
	hash.Write([]byte("cramershoup_secret")) //XXX: change me!
	hash.Read(out[:])

	return ed448.NewScalar(out[:]), nil
}
