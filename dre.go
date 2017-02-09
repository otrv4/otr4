package otr4

import (
	"github.com/twstrike/ed448"
	"golang.org/x/crypto/sha3"
)

func auth(rand func() []ed448.Scalar, ourPub, theirPub, theirPubEcdh ed448.Point, ourSec ed448.Scalar, message []byte) []byte {
	rv := rand()
	t1, c2, c3, r2, r3 := rv[0], rv[1], rv[2], rv[3], rv[4]
	pt1 := ed448.PointScalarMul(ed448.BasePoint, t1)
	pt2 := ed448.DoubleScalarMul(ed448.BasePoint, theirPub, r2, c2)
	pt3 := ed448.DoubleScalarMul(ed448.BasePoint, theirPubEcdh, r3, c3)
	values := concat(ed448.BasePoint, ed448.ScalarQ, ourPub,
		theirPub, theirPubEcdh, pt1, pt2, pt3, message)
	c := hashToScalar(values)
	c1, r1 := ed448.NewDecafScalar([56]byte{}), ed448.NewDecafScalar([56]byte{})
	c1.Sub(c, c2)
	c1.Sub(c1, c3)
	r1.Mul(c1, ourSec)
	r1.Sub(t1, r1)
	sigma := concat(c1, r1, c2, r2, c3, r3)
	return sigma
}

func hashToScalar(in []byte) ed448.Scalar {
	hash := make([]byte, 56)
	sha3.ShakeSum256(hash, in)
	s := ed448.NewDecafScalar([56]byte{})
	s.Decode(hash)
	return s
}

func concat(bytes ...interface{}) (b []byte) {
	if len(bytes) < 2 {
		panic("missing concat arguments")
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
			panic("not a valid input")
		}
	}
	return b
}
