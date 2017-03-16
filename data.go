package otr4

import (
	"github.com/twstrike/ed448"
	"golang.org/x/crypto/sha3"
)

func hashToScalar(in []byte) ed448.Scalar {
	hash := make([]byte, fieldBytes)
	sha3.ShakeSum256(hash, in)
	s := ed448.NewScalar(hash)
	return s
}

func appendBytes(bytes ...interface{}) (b []byte) {
	if len(bytes) < 2 {
		panic("programmer error: missing append arguments")
	}
	for _, e := range bytes {
		switch i := e.(type) {
		case ed448.Point:
			b = append(b, i.Encode()...)
		case ed448.Scalar:
			b = append(b, i.Encode()...)
		case []byte:
			b = append(b, i...)
		default:
			panic("programmer error: invalid input")
		}
	}
	return b
}

func appendAndHash(bytes ...interface{}) ed448.Scalar {
	return hashToScalar(appendBytes(bytes...))
}

func appendPoint(l []byte, r ed448.Point) []byte {
	return append(l, r.Encode()...)
}
