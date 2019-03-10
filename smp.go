package otr4

import (
	"github.com/otrv4/ed448"
	"golang.org/x/crypto/sha3"
)

const smpVersion = 1

func generateSMPsecret(initiatorFingerprint, receiverFingerprint, ssid, secret []byte) []byte {
	h := sha3.New512()
	h.Write([]byte{smpVersion})
	h.Write(initiatorFingerprint)
	h.Write(receiverFingerprint)
	h.Write(ssid)
	h.Write(secret)
	return h.Sum(nil)
}

func generateDZKP(r, a, c ed448.Scalar) ed448.Scalar {
	a.Mul(a, c)
	r.Sub(r, a)
	return r
}

func generateZKP(r, a ed448.Scalar, ix byte) (ed448.Scalar, ed448.Scalar) {
	gr := ed448.PrecomputedScalarMul(r)
	c := hashToScalar(ix, gr)
	d := generateDZKP(r, a, c)

	return c, d
}

func verifyZKP(d, c ed448.Scalar, g ed448.Point, ix byte) bool {
	r := ed448.PrecomputedScalarMul(d)
	s := ed448.PointScalarMul(g, c)
	p := ed448.NewPointFromBytes()
	p.Add(r, s)
	t := hashToScalar(ix, p)
	return c.Equals(t)
}

func verifyZKP2(g2, g3, pb, qb ed448.Point, d5, d6, cp ed448.Scalar, ix byte) bool {
	l := ed448.PointDoubleScalarMul(g3, pb, d5, cp)
	r := ed448.PointDoubleScalarMul(ed448.BasePoint, g2, d5, d6)
	s := ed448.PointScalarMul(qb, cp)
	r.Add(r, s)
	t := hashToScalar(ix, l, r)
	return cp.Equals(t)
}

func verifyZKP3(g2, g3, pa, qa ed448.Point, d5, d6, cp ed448.Scalar, ix byte) bool {
	l := ed448.PointDoubleScalarMul(g3, pa, d5, cp)
	r := ed448.PointDoubleScalarMul(ed448.BasePoint, g2, d5, d6)
	s := ed448.PointScalarMul(qa, cp)
	r.Add(r, s)
	t := hashToScalar(ix, l, r)
	return cp.Equals(t)
}

func verifyZKP4(g3a, qa, qb, ra ed448.Point, d7, cr ed448.Scalar, ix byte) bool {
	s := ed448.NewPointFromBytes()
	s.Sub(qa, qb)
	l := ed448.PointDoubleScalarMul(ed448.BasePoint, g3a, d7, cr)
	r := ed448.PointDoubleScalarMul(s, ra, d7, cr)
	t := hashToScalar(ix, l, r)
	return cr.Equals(t)
}
