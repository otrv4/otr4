package otr4

import (
	"io"

	"github.com/twstrike/ed448"
)

type drCipher struct {
	u11, u21, e1, v1, u12, u22, e2, v2 ed448.Point
}

type nIZKProof struct {
	l, n1, n2 ed448.Scalar // XXX: this should be big.Int or MPI or byte[]?
}

type drMessage struct {
	cipher drCipher
	proof  nIZKProof
}

func (gamma *drMessage) drEnc(message []byte, rand io.Reader, pub1, pub2 *cramerShoupPublicKey) (err error) {
	err = isValidPublicKey(pub1, pub2)
	if err != nil {
		return
	}

	k1, err := randScalar(rand)
	if err != nil {
		return
	}
	k2, err := randScalar(rand)
	if err != nil {
		return
	}

	// u1i = G1*ki, u2i = G2*ki
	gamma.cipher.u11 = ed448.PointScalarMul(ed448.BasePoint, k1)
	gamma.cipher.u21 = ed448.PointScalarMul(g2, k1)
	gamma.cipher.u12 = ed448.PointScalarMul(ed448.BasePoint, k2)
	gamma.cipher.u22 = ed448.PointScalarMul(g2, k2)

	// ei = (hi*ki) + m
	m := ed448.NewPointFromBytes(message)
	gamma.cipher.e1 = ed448.PointScalarMul(pub1.h, k1)
	gamma.cipher.e1.Add(gamma.cipher.e1, m)
	gamma.cipher.e2 = ed448.PointScalarMul(pub2.h, k2)
	gamma.cipher.e2.Add(gamma.cipher.e2, m)

	// αi = H(u1i,u2i,ei)
	alpha1 := appendAndHash(gamma.cipher.u11, gamma.cipher.u21, gamma.cipher.e1)
	alpha2 := appendAndHash(gamma.cipher.u12, gamma.cipher.u22, gamma.cipher.e2)

	// ai = ci * ki
	// bi = di*(ki * αi)
	// vi = ai + bi
	a1 := ed448.PointScalarMul(pub1.c, k1)
	b1 := ed448.PointScalarMul(pub1.d, k1)
	gamma.cipher.v1 = ed448.PointScalarMul(b1, alpha1)
	gamma.cipher.v1.Add(a1, gamma.cipher.v1)
	a2 := ed448.PointScalarMul(pub2.c, k2)
	b2 := ed448.PointScalarMul(pub2.d, k2)
	gamma.cipher.v2 = ed448.PointScalarMul(b2, alpha2)
	gamma.cipher.v2.Add(a2, gamma.cipher.v2)

	err = gamma.proof.genNIZKPK(rand, &gamma.cipher, pub1, pub2, alpha1, alpha2, k1, k2)
	if err != nil {
		return
	}

	return nil
}

// XXX: the indexes may not be necessary
func (gamma *drMessage) drDec(pub1, pub2 *cramerShoupPublicKey, priv *cramerShoupPrivateKey, index int) (message []byte, err error) {
	err = isValidPublicKey(pub1, pub2)
	if err != nil {
		return nil, err
	}

	// αj = HashToScalar(U1j || U2j || Ej)
	alpha1 := appendAndHash(gamma.cipher.u11, gamma.cipher.u21, gamma.cipher.e1)
	alpha2 := appendAndHash(gamma.cipher.u12, gamma.cipher.u22, gamma.cipher.e2)

	valid, err := gamma.proof.verifyNIZKPK(&gamma.cipher, pub1, pub2, alpha1, alpha2)
	if !valid {
		return nil, err
	}

	var m ed448.Point
	if index == 1 {
		valid, err = verifyDRMessage(gamma.cipher.u11, gamma.cipher.u21, gamma.cipher.v1, alpha1, priv)
		if !valid {
			return nil, err
		}
		// m = e - u11*z
		m = ed448.PointScalarMul(gamma.cipher.u11, priv.z)
		m.Sub(gamma.cipher.e1, m)
	} else {
		valid, err = verifyDRMessage(gamma.cipher.u12, gamma.cipher.u22, gamma.cipher.v2, alpha2, priv)
		if !valid {
			return nil, err
		}
		// m = e - u12*z
		m = ed448.PointScalarMul(gamma.cipher.u12, priv.z)
		m.Sub(gamma.cipher.e2, m)
	}

	message = m.Encode()
	return
}

func (pf *nIZKProof) genNIZKPK(rand io.Reader, m *drCipher, pub1, pub2 *cramerShoupPublicKey, alpha1, alpha2, k1, k2 ed448.Scalar) error {
	t1, err := randScalar(rand)
	if err != nil {
		return err
	}
	t2, err := randScalar(rand)
	if err != nil {
		return err
	}

	// T11 = G1 * t2
	t11 := ed448.PointScalarMul(ed448.BasePoint, t1)
	// T21 = G2 * t1
	t21 := ed448.PointScalarMul(g2, t1)
	// T31 = (C1 + D1 * α1) * t1
	t31 := ed448.PointScalarMul(pub1.d, alpha1)
	t31.Add(pub1.c, t31)
	t31 = ed448.PointScalarMul(t31, t1)

	// T12 = G1 * t2
	t12 := ed448.PointScalarMul(ed448.BasePoint, t2)
	// T22 = G2 * t2
	t22 := ed448.PointScalarMul(g2, t2)
	// T32 = (C2 + D2 * α2) * t2
	t32 := ed448.PointScalarMul(pub2.d, alpha2)
	t32.Add(pub2.c, t32)
	t32 = ed448.PointScalarMul(t32, t2)

	// T4 = H1 * t1 - H2 * t2
	a := ed448.PointScalarMul(pub1.h, t1)
	t4 := ed448.PointScalarMul(pub2.h, t2)
	t4.Sub(a, t4)

	// gV = G1 || G2 || q
	gV := appendBytes(ed448.BasePoint, g2, ed448.ScalarQ)
	// pV = C1 || D1 || H1 || C2 || D2 || H2
	pV := appendBytes(pub1.c, pub1.d, pub1.h, pub2.c, pub2.d, pub2.h)
	// eV = U11 || U21 || E1 || V1 || α1 || U12 || U22 || E2 || V2 || α2
	eV := appendBytes(m.u11, m.u21, m.e1, m.v1, alpha1, m.u12, m.u22, m.e2, m.v2, alpha2)
	// zV = T11 || T21 || T31 || T12 || T22 || T32 || T4
	zV := appendBytes(t11, t21, t31, t12, t22, t32, t4)

	pf.l = appendAndHash(gV, pV, eV, zV)

	// ni = ti - l * ki (mod q)
	pf.n1 = ed448.NewDecafScalar(nil)
	pf.n2 = ed448.NewDecafScalar(nil)
	pf.n1.Mul(pf.l, k1)
	pf.n1.Sub(t1, pf.n1)

	pf.n2.Mul(pf.l, k2)
	pf.n2.Sub(t2, pf.n2)

	return nil
}

func (pf *nIZKProof) verifyNIZKPK(m *drCipher, pub1, pub2 *cramerShoupPublicKey, alpha1, alpha2 ed448.Scalar) (bool, error) {
	// T1j = G1 * nj + U1j * l
	t11 := ed448.DoubleScalarMul(ed448.BasePoint, m.u11, pf.n1, pf.l)
	// T2j = G2 * nj + U2j * l
	t21 := ed448.DoubleScalarMul(g2, m.u21, pf.n1, pf.l)
	// T3j = (Cj + Dj * αj) * nj + Vj * l
	t31 := ed448.PointScalarMul(pub1.d, alpha1)
	t31.Add(pub1.c, t31)
	t31 = ed448.DoubleScalarMul(t31, m.v1, pf.n1, pf.l)

	// T1j = G1 * nj + U1j * l
	t12 := ed448.DoubleScalarMul(ed448.BasePoint, m.u12, pf.n2, pf.l)
	// T2j = G2 * nj + U2j * l
	t22 := ed448.DoubleScalarMul(g2, m.u22, pf.n2, pf.l)
	// T3j = (Cj + Dj * αj) * nj + Vj * l
	t32 := ed448.PointScalarMul(pub2.d, alpha2)
	t32.Add(pub2.c, t32)
	t32 = ed448.DoubleScalarMul(t32, m.v2, pf.n2, pf.l)

	// T4 = H1 * n1 - H2 * n2 + (E1-E2) * l
	// a = H1 * n1
	// b = H2 * n2 - a
	c := ed448.NewPointFromBytes(nil)
	a := ed448.PointScalarMul(pub1.h, pf.n1)
	b := ed448.PointScalarMul(pub2.h, pf.n2)
	b.Sub(a, b)
	c.Sub(m.e1, m.e2)
	t4 := ed448.PointScalarMul(c, pf.l)
	t4.Add(b, t4)

	// gV = G1 || G2 || q
	gV := appendBytes(ed448.BasePoint, g2, ed448.ScalarQ)
	// pV = C1 || D1 || H1 || C2 || D2 || H2
	pV := appendBytes(pub1.c, pub1.d, pub1.h, pub2.c, pub2.d, pub2.h)
	// eV = U11 || U21 || E1 || V1 || α1 || U12 || U22 || E2 || V2 || α2
	eV := appendBytes(m.u11, m.u21, m.e1, m.v1, alpha1, m.u12, m.u22, m.e2, m.v2, alpha2)
	// zV = T11 || T21 || T31 || T12 || T22 || T32 || T4
	zV := appendBytes(t11, t21, t31, t12, t22, t32, t4)

	// l' = HashToScalar(gV || pV || eV || zV)
	ll := appendAndHash(gV, pV, eV, zV)

	valid := pf.l.Equals(ll)

	if !valid {
		return false, errImpossibleToDecrypt
	}
	return true, nil
}

func auth(rand io.Reader, ourPub, theirPub, theirPubEcdh ed448.Point, ourSec ed448.Scalar, message []byte) ([]byte, error) {
	ap, err := generateAuthParams(rand, 5)
	if err != nil {
		return nil, err
	}
	t1, c2, c3, r2, r3 := ap[0], ap[1], ap[2], ap[3], ap[4]
	pt1 := ed448.PointScalarMul(ed448.BasePoint, t1)
	pt2 := ed448.DoubleScalarMul(ed448.BasePoint, theirPub, r2, c2)
	pt3 := ed448.DoubleScalarMul(ed448.BasePoint, theirPubEcdh, r3, c3)
	c := appendAndHash(ed448.BasePoint, ed448.ScalarQ, ourPub, theirPub, theirPubEcdh, pt1, pt2, pt3, message)
	c1, r1 := ed448.NewDecafScalar(nil), ed448.NewDecafScalar(nil)
	c1.Sub(c, c2)
	c1.Sub(c1, c3)
	r1.Mul(c1, ourSec)
	r1.Sub(t1, r1)
	sigma := appendBytes(c1, r1, c2, r2, c3, r3)
	return sigma, err
}

func verify(theirPub, ourPub, ourPubEcdh ed448.Point, sigma, message []byte) bool {
	ps := parseScalar(sigma)
	c1, r1, c2, r2, c3, r3 := ps[0], ps[1], ps[2], ps[3], ps[4], ps[5]
	pt1 := ed448.DoubleScalarMul(ed448.BasePoint, theirPub, r1, c1)
	pt2 := ed448.DoubleScalarMul(ed448.BasePoint, ourPub, r2, c2)
	pt3 := ed448.DoubleScalarMul(ed448.BasePoint, ourPubEcdh, r3, c3)
	c := appendAndHash(ed448.BasePoint, ed448.ScalarQ, theirPub, ourPub, ourPubEcdh, pt1, pt2, pt3, message)
	out := ed448.NewDecafScalar(nil)
	out.Add(c1, c2)
	out.Add(out, c3)
	return c.Equals(out)
}

func isValidPublicKey(pubs ...*cramerShoupPublicKey) error {
	for _, pub := range pubs {
		if !(pub.c.IsValid() && pub.d.IsValid() && pub.h.IsValid()) {
			return errInvalidPublicKey
		}
	}
	return nil
}

func verifyDRMessage(u1, u2, v ed448.Point, alpha ed448.Scalar, priv *cramerShoupPrivateKey) (bool, error) {
	// U1i * x1i + U2i * x2i + (U1i * y1i + U2i * y2i) * αi ≟ Vi
	// a = (u11*x1)+(u21*x2)
	a := ed448.DoubleScalarMul(u1, u2, priv.x1, priv.x2)
	// b = (u11*y1)+(u21*y2)
	b := ed448.DoubleScalarMul(u1, u2, priv.y1, priv.y2)
	c := ed448.PointScalarMul(b, alpha)
	c.Add(a, c)

	valid := c.Equals(v)
	if !valid {
		//XXX: is this the correct err?
		return false, errImpossibleToDecrypt
	}
	return valid, nil
}

func generateAuthParams(rand io.Reader, n int) ([]ed448.Scalar, error) {
	var out []ed448.Scalar
	for i := 0; i < n; i++ {
		scalar, err := randScalar(rand)
		if err != nil {
			return nil, err
		}
		out = append(out, scalar)
	}
	return out, nil
}
