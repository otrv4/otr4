package otr4

import (
	"io"

	"github.com/twstrike/ed448"
	"golang.org/x/crypto/sha3"
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

func drEnc(message []byte, rand io.Reader, pub1, pub2 *cramerShoupPublicKey) (ed448.Point, ed448.Point, error) {
	k1, err := randScalar(rand)
	if err != nil {
		return nil, nil, err
	}
	k2, err := randScalar(rand)
	if err != nil {
		return nil, nil, err
	}

	// u = G1*r, u2 = G2*r
	u11 := ed448.PointScalarMul(ed448.BasePoint, k1)
	u21 := ed448.PointScalarMul(g2, k1)
	u12 := ed448.PointScalarMul(ed448.BasePoint, k2)
	u22 := ed448.PointScalarMul(g2, k2)

	// e = (h*r) + m
	m := ed448.NewPointFromBytes(nil)
	m.Decode(message, false)

	e1 := ed448.PointScalarMul(pub1.h, k1)
	e1.Add(e1, m)
	e2 := ed448.PointScalarMul(pub2.h, k2)
	e2.Add(e2, m)

	// α = H(u1,u2,e)
	al1 := concat(u11, u21, e1)
	hash1 := sha3.NewShake256()
	hash1.Write(al1)
	var alpha1 [fieldBytes]byte
	hash1.Read(alpha1[:])

	al2 := concat(u12, u22, e2)
	hash2 := sha3.NewShake256()
	hash2.Write(al2)
	var alpha2 [fieldBytes]byte
	hash2.Read(alpha2[:])

	// a = c * r
	// b = d*(r * alpha)
	// v = s + t
	a1 := ed448.PointScalarMul(pub1.c, k1)
	b1 := ed448.PointScalarMul(pub1.d, k1)
	b1 = ed448.PointScalarMul(b1, ed448.NewDecafScalar(alpha1[:]))
	v1 := ed448.NewPointFromBytes(nil)
	v1.Add(a1, b1)

	a2 := ed448.PointScalarMul(pub2.c, k2)
	b2 := ed448.PointScalarMul(pub2.d, k2)
	b2 = ed448.PointScalarMul(b2, ed448.NewDecafScalar(alpha2[:]))
	v2 := ed448.NewPointFromBytes(nil)
	v2.Add(a2, b2)

func (pf *nIZKProof) genNIZKPK(rand io.Reader, m *drCipher, pub1, pub2 *cramerShoupPublicKey, alpha1, alpha2, k1, k2 ed448.Scalar) error {

	bytes1 := make([]byte, fieldBytes)
	t1, err := randScalar(rand, bytes1)
	if err != nil {
		return err
	}

	bytes2 := make([]byte, fieldBytes)
	t2, err := randScalar(rand, bytes2)
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
	t4 := ed448.NewPointFromBytes(nil)
	a := ed448.PointScalarMul(pub1.h, t1)
	b := ed448.PointScalarMul(pub2.h, t2)
	t4.Sub(a, b)

	// gV = G1 || G2 || q
	gV := concat(ed448.BasePoint, g2, ed448.ScalarQ)
	// pV = C1 || D1 || H1 || C2 || D2 || H2
	pV := concat(pub1.c, pub1.d, pub1.h, pub2.c, pub2.d, pub2.h)
	// eV = U11 || U21 || E1 || V1 || α1 || U12 || U22 || E2 || V2 || α2
	eV := concat(m.u11, m.u21, m.e1, m.v1, alpha1, m.u12, m.u22, m.e2, m.v2, alpha2)
	// zV = T11 || T21 || T31 || T12 || T22 || T32 || T4
	zV := concat(t11, t21, t31, t12, t22, t32, t4)

	hash := sha3.NewShake256()
	hash.Write(gV)
	hash.Write(pV)
	hash.Write(eV)
	hash.Write(zV)
	var l [fieldBytes]byte
	hash.Read(l[:])

	pf.l = ed448.NewDecafScalar(l[:])

	// ni = ti - l * ki (mod q)
	pf.n1 = ed448.NewDecafScalar(nil)
	pf.n2 = ed448.NewDecafScalar(nil)
	pf.n1.Mul(pf.l, k1)
	pf.n1.Sub(t1, pf.n1)
	pf.n2.Mul(pf.l, k2)
	pf.n2.Sub(t2, pf.n2)

	return nil
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
	c := concatAndHash(ed448.BasePoint, ed448.ScalarQ, ourPub, theirPub, theirPubEcdh, pt1, pt2, pt3, message)
	c1, r1 := ed448.NewDecafScalar(nil), ed448.NewDecafScalar(nil)
	c1.Sub(c, c2)
	c1.Sub(c1, c3)
	r1.Mul(c1, ourSec)
	r1.Sub(t1, r1)
	sigma := concat(c1, r1, c2, r2, c3, r3)
	return sigma, err
}

func verify(theirPub, ourPub, ourPubEcdh ed448.Point, sigma, message []byte) bool {
	ps := parse(sigma)
	c1, r1, c2, r2, c3, r3 := ps[0], ps[1], ps[2], ps[3], ps[4], ps[5]
	pt1 := ed448.DoubleScalarMul(ed448.BasePoint, theirPub, r1, c1)
	pt2 := ed448.DoubleScalarMul(ed448.BasePoint, ourPub, r2, c2)
	pt3 := ed448.DoubleScalarMul(ed448.BasePoint, ourPubEcdh, r3, c3)
	c := concatAndHash(ed448.BasePoint, ed448.ScalarQ, theirPub, ourPub, ourPubEcdh, pt1, pt2, pt3, message)
	out := ed448.NewDecafScalar(nil)
	out.Add(c1, c2)
	out.Add(out, c3)
	return c.Equals(out)
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

func parse(bytes []byte) []ed448.Scalar {
	var out []ed448.Scalar
	for i := 0; i < len(bytes); i += fieldBytes {
		out = append(out, ed448.NewDecafScalar(bytes[i:i+fieldBytes]))
	}
	return out
}

// XXX: unify this with parse()
func parsePoint(bytes []byte) []ed448.Point {
	var out []ed448.Point
	for i := 0; i < len(bytes); i += fieldBytes {
		out = append(out, ed448.NewPointFromBytes(bytes[i:i+fieldBytes]))
	}
	return out
}

func concat(bytes ...interface{}) (b []byte) {
	if len(bytes) < 2 {
		panic("programmer error: missing concat arguments")
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

func concatAndHash(bytes ...interface{}) ed448.Scalar {
	return hashToScalar(concat(bytes...))
}
