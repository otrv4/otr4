package otr4

import (
	"errors"
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

func deriveCramerShoupKeys(rand io.Reader) (*cramerShoupPrivateKey, *cramerShoupPublicKey, error) {

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

	err := isValidPublicKey(pub)

	if err != nil {
		return nil, nil, err
	}

	return priv, pub, err
}

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
	m := ed448.NewPointFromBytes(nil)
	m.Decode(message, false)
	e := ed448.PointScalarMul(pub.h, r)
	e.Add(e, m)

	// α = H(u1,u2,e)
	a := concat(u1, u2, e)
	hash := sha3.NewShake256()
	hash.Write(a)
	var alpha [fieldBytes]byte
	hash.Read(alpha[:])

	// v = c*r + d*(r * alpha)
	tmp := ed448.NewDecafScalar(nil)
	tmp.Mul(r, ed448.NewDecafScalar(alpha[:]))
	v := ed448.DoubleScalarMul(pub.c, pub.d, r, tmp)

	cipher := concat(u1, u2, e, v)
	return cipher, nil
}

func cramerShoupDec(cipher []byte, priv *cramerShoupPrivateKey) (message []byte, err error) {

	c := parsePoint(cipher)
	u1, u2, e, v := c[0], c[1], c[2], c[3]

	// alpha = H(u1,u2,e)
	a := concat(u1, u2, e)
	hash := sha3.NewShake256()
	hash.Write(a)
	var alpha [56]byte
	hash.Read(alpha[:])

	// (u1*(x1+y1*alpha) +u2*(x2+ y2*alpha) == v
	// (u1*x1)+(u2*x2)
	tmpU1 := ed448.DoubleScalarMul(u1, u2, priv.x1, priv.x2)
	// (u1*y1)+(u2*y2)
	tmpU2 := ed448.DoubleScalarMul(u1, u2, priv.y1, priv.y2)
	tmpV := ed448.PointScalarMul(tmpU2, ed448.NewDecafScalar(alpha[:]))
	tmpV.Add(tmpU1, tmpV)

	valid := tmpV.Equals(v)

	if !valid {
		err = errors.New("verification of cipher failed")
		return nil, err
	}

	// m = e - u1*z
	m := ed448.PointScalarMul(u1, priv.z)
	m.Sub(e, m)
	message = m.Encode()

	return
}

func isValidPublicKey(pub *cramerShoupPublicKey) error {
	if !(pub.c.IsValid() && pub.d.IsValid() && pub.h.IsValid()) {
		return errInvalidPublicKey
	}
	return nil
}
