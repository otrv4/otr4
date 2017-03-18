package otr4

import (
	"io"

	"github.com/twstrike/ed448"
)

// XXX: serialize as MPI
type cramerShoupPrivateKey struct {
	x1, x2, y1, y2, z ed448.Scalar
}

type cramerShoupPublicKey struct {
	c, d, h ed448.Point
}

type cramerShoupMessage struct {
	u1, u2, e, v ed448.Point
}

//XXX: make random part of something else: conversation?
func deriveCramerShoupPrivKey(rand io.Reader) (*cramerShoupPrivateKey, error) {
	priv := &cramerShoupPrivateKey{}
	var err1, err2, err3, err4, err5 error

	priv.x1, err1 = randLongTermScalar(rand)
	priv.x2, err2 = randLongTermScalar(rand)
	priv.y1, err3 = randLongTermScalar(rand)
	priv.y2, err4 = randLongTermScalar(rand)
	priv.z, err5 = randLongTermScalar(rand)

	return priv, firstError(err1, err2, err3, err4, err5)
}

//XXX: make this return a keyPair
func deriveCramerShoupKeys(rand io.Reader) (*cramerShoupPrivateKey, *cramerShoupPublicKey, error) {
	priv, err := deriveCramerShoupPrivKey(rand)
	if err != nil {
		return nil, nil, err
	}
	pub := &cramerShoupPublicKey{}
	pub.c = ed448.PointDoubleScalarMul(ed448.BasePoint, g2, priv.x1, priv.x2)
	pub.d = ed448.PointDoubleScalarMul(ed448.BasePoint, g2, priv.y1, priv.y2)
	pub.h = ed448.PointScalarMul(ed448.BasePoint, priv.z)
	return priv, pub, nil
}

func (csm *cramerShoupMessage) cramerShoupEnc(message []byte, rand io.Reader, pub *cramerShoupPublicKey) error {
	r, err := randScalar(rand)
	if err != nil {
		return err
	}

	// u = G1*r, u2 = G2*r
	csm.u1 = ed448.PointScalarMul(ed448.BasePoint, r)
	csm.u2 = ed448.PointScalarMul(g2, r)

	// e = (h*r) + m
	m := ed448.NewPointFromBytes()
	m.Decode(message, false)
	csm.e = ed448.PointScalarMul(pub.h, r)
	csm.e.Add(csm.e, m)

	// α = H(u1,u2,e)
	alpha := appendAndHash(csm.u1, csm.u2, csm.e)

	// a = c * r
	// b = d*(r * alpha)
	// v = s + t
	a := ed448.PointScalarMul(pub.c, r)
	b := ed448.PointScalarMul(pub.d, r)
	b = ed448.PointScalarMul(b, alpha)
	csm.v = ed448.NewPointFromBytes()
	csm.v.Add(a, b)
	return nil
}

func (csm *cramerShoupMessage) cramerShoupDec(priv *cramerShoupPrivateKey) (message []byte, err error) {
	// alpha = H(u1,u2,e)
	alpha := appendAndHash(csm.u1, csm.u2, csm.e)

	// (u1*(x1+y1*alpha) +u2*(x2+ y2*alpha) == v
	// a = (u1*x1)+(u2*x2)
	a := ed448.PointDoubleScalarMul(csm.u1, csm.u2, priv.x1, priv.x2)

	// b = (u1*y1)+(u2*y2)
	b := ed448.PointDoubleScalarMul(csm.u1, csm.u2, priv.y1, priv.y2)
	v0 := ed448.PointScalarMul(b, alpha)
	v0.Add(a, v0)
	valid := v0.Equals(csm.v)
	if !valid {
		return nil, errImpossibleToDecrypt
	}

	// m = e - u1*z
	m := ed448.PointScalarMul(csm.u1, priv.z)
	m.Sub(csm.e, m)
	message = m.Encode()
	return
}
