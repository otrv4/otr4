package otr4

import (
	"github.com/twstrike/ed448"
	"golang.org/x/crypto/sha3"
)

func hashToScalar(in []byte) ed448.Scalar {
	hash := make([]byte, fieldBytes)
	sha3.ShakeSum256(hash, in)
	s := ed448.NewDecafScalar(nil)
	s.Decode(hash)
	return s
}
