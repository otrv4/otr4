package otr4

import (
	"io"

	"github.com/otrv4/ed448"
)

type authMessage struct {
	c1, r1, c2, r2, c3, r3 ed448.Scalar // XXX: serialize as MPI
}

func (sigma *authMessage) generateAuthParams(rand io.Reader) error {
	var err1, err2, err3, err4 error

	sigma.c2, err1 = randScalar(rand)
	sigma.c3, err2 = randScalar(rand)
	sigma.r2, err3 = randScalar(rand)
	sigma.r3, err4 = randScalar(rand)

	return firstError(err1, err2, err3, err4)
}

func (sigma *authMessage) auth(rand io.Reader, ourPub, theirPub, theirPubEcdh ed448.Point, ourSec ed448.Scalar, message []byte) error {
	t1, err := randScalar(rand)
	if err != nil {
		return err
	}

	err = sigma.generateAuthParams(rand)
	if err != nil {
		return err
	}

	pt1 := ed448.PointScalarMul(ed448.BasePoint, t1)
	pt2 := ed448.PointDoubleScalarMul(ed448.BasePoint, theirPub, sigma.r2, sigma.c2)
	pt3 := ed448.PointDoubleScalarMul(ed448.BasePoint, theirPubEcdh, sigma.r3, sigma.c3)
	c := appendAndHash(ed448.BasePoint, ed448.ScalarQ, ourPub, theirPub, theirPubEcdh, pt1, pt2, pt3, message)
	sigma.c1, sigma.r1 = ed448.NewScalar(), ed448.NewScalar()
	sigma.c1.Sub(c, sigma.c2)
	sigma.c1.Sub(sigma.c1, sigma.c3)
	sigma.r1.Mul(sigma.c1, ourSec)
	sigma.r1.Sub(t1, sigma.r1)
	return nil
}

func (sigma *authMessage) verify(theirPub, ourPub, ourPubEcdh ed448.Point, message []byte) bool {
	pt1 := ed448.PointDoubleScalarMul(ed448.BasePoint, theirPub, sigma.r1, sigma.c1)
	pt2 := ed448.PointDoubleScalarMul(ed448.BasePoint, ourPub, sigma.r2, sigma.c2)
	pt3 := ed448.PointDoubleScalarMul(ed448.BasePoint, ourPubEcdh, sigma.r3, sigma.c3)
	c := appendAndHash(ed448.BasePoint, ed448.ScalarQ, theirPub, ourPub, ourPubEcdh, pt1, pt2, pt3, message)
	out := ed448.NewScalar()
	out.Add(sigma.c1, sigma.c2)
	out.Add(out, sigma.c3)
	return c.Equals(out)
}
