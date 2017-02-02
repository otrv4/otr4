package otr4

import (
	"errors"
	"github.com/twstrike/ed448"
	"golang.org/x/crypto/sha3"
)

type bigNumber [56]byte

//TODO
func auth(aPub, bPub, bPubEcdh *publicKey, aSec *secretKey, message []byte) (sigma [6]bigNumber) {
	// message := "hello"
	// t1, c2, c3, r2, r3 []byte || [16]uint32 := rand(q)
	// T1 := ed448.MulByBase(t1)
	// T2 := ed448.Add(ed448.MulByBase(r2), ed448.Mul(bPub, c2))
	// T3 := ed448.Add(ed448.MulByBase(r3), ed448.Mul(bPubEcdh, c3))
	// values := concat(basePoint, primeOrder, aPub, bPub, bPubEcdh, T1, T2, T3, message)
	// c := hashToScalar(values)
	// c1 := ed448.ModQ(ed448.Sub(ed448.Sub(c, c2), c3))
	// r1 := ed448.ModQ(ed448.Sub(t1, ed448.Mul(c1, a2)))
	// sigma = []bigNumber{c1, r1, c2, r2, c3, r3}
	return
}

func hashToScalar(in []byte) (scalar ed448.Scalar) {
	hash := sha3.Sum512(in)
	s := ed448.NewDecafScalar([56]byte{})
	s.Decode(hash[:])
	return s
}

func concat(bytes ...[]byte) ([]byte, error) {
	b := []byte{}
	if len(bytes) < 2 {
		return nil, errors.New("missing concat arguments")
	}
	for i := range bytes {
		b = append(b, bytes[i]...)
	}

	return b, nil
}
