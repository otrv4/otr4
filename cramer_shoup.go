package otr4

import (
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/twstrike/ed448"
)

// XXX: use bytes?
type cramerShoupPrivateKey struct {
	x1, x2, y1, y2, z ed448.Scalar
}

type cramerShoupPublicKey struct {
	c, d, h ed448.Point
}

func deriveCramerShoupKeys(rand io.Reader) (*cramerShoupPrivateKey, *cramerShoupPublicKey) {

	priv := &cramerShoupPrivateKey{}
	pub := &cramerShoupPublicKey{}

	priv.x1 = randLongTermScalar(rand)
	priv.x2 = randLongTermScalar(rand)
	priv.y1 = randLongTermScalar(rand)
	priv.y2 = randLongTermScalar(rand)
	priv.z = randLongTermScalar(rand)

	pub.c = ed448.DoubleScalarMul(ed448.BasePoint, g2, priv.x1, priv.x2)
	pub.d = ed448.DoubleScalarMul(ed448.BasePoint, g2, priv.y1, priv.y2)
	pub.h = ed448.PointScalarMul(ed448.BasePoint, priv.z)

	return priv, pub
}

// Part of cramer shoup suite
// XXX: use a receiver
func cramerShoupEnc(message []byte, rand io.Reader, pub *cramerShoupPublicKey) ([]byte, error) {

	b := make([]byte, fieldBytes)
	r, err := randScalar(rand, b)
	if err != nil {
		return nil, err
	}

	// u = G1*r, u2 = G2*r
	u1 := ed448.PointScalarMul(ed448.BasePoint, r)
	u2 := ed448.PointScalarMul(g2, r)

	// e = (h*r) + m
	m := ed448.NewPoint([16]uint32{}, [16]uint32{}, [16]uint32{}, [16]uint32{})
	m.Decode(message, false)
	e := ed448.PointScalarMul(pub.h, r)
	e.Add(e, m)

	// α = H(u1,u2,e)
	a := concat(u1, u2, e)
	hash := sha3.NewShake256()
	hash.Write(a)
	var alpha [fieldBytes]byte
	hash.Read(alpha[:])

	// v = c*r + d*(r * α)
	tmp := ed448.NewDecafScalar(nil)
	tmp.Mul(r, ed448.NewDecafScalar(alpha[:]))
	v := ed448.DoubleScalarMul(pub.c, pub.d, r, tmp)

	cipher := concat(u1, u2, e, v)
	return cipher, nil
}

func randLongTermScalar(rand io.Reader) ed448.Scalar {
	b := make([]byte, fieldBytes)
	randScalar(rand, b)
	hash := sha3.NewShake256()
	hash.Write(b)
	hash.Write([]byte("cramershoup_secret"))
	var out [fieldBytes]byte //is it ok? use 64 instead?
	hash.Read(out[:])
	return ed448.NewDecafScalar(out[:])
}
