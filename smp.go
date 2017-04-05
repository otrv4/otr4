package otr4

import (
	"github.com/twstrike/ed448"
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

func verifyZKP(d, c ed448.Scalar, gen ed448.Point, ix byte) bool {
	r := ed448.PrecomputedScalarMul(d)
	s := ed448.PointScalarMul(gen, c)
	p := ed448.NewPointFromBytes()
	p.Add(r, s)
	t := hashToScalar(ix, p)
	return c.Equals(t)
}
