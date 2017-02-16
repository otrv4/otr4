package otr4

import (
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/twstrike/ed448"
)

type cramerShoupPrivateKey struct {
	x1, x2, y1, y2, z ed448.Scalar
}

type cramerShoupPublicKey struct {
	c, d, h ed448.Point
}

// XXX: separate this function?
func deriveCramerShoupKeys(rand io.Reader) (priv cramerShoupPrivateKey, pub cramerShoupPublicKey) {

	priv.x1 = randomLongTermScalar(rand)
	priv.x2 = randomLongTermScalar(rand)
	priv.y1 = randomLongTermScalar(rand)
	priv.y2 = randomLongTermScalar(rand)
	priv.z = randomLongTermScalar(rand)

	pub.c = ed448.DoubleScalarMul(ed448.BasePoint, g2, priv.x1, priv.x2)
	pub.d = ed448.DoubleScalarMul(ed448.BasePoint, g2, priv.y1, priv.y2)
	pub.h = ed448.PointScalarMul(ed448.BasePoint, priv.z)

	return priv, pub
}

func randomLongTermScalar(rand io.Reader) ed448.Scalar {

	b := make([]byte, fieldBytes)
	randScalar(rand, b)
	hash := sha3.NewShake256()
	hash.Write(b)
	hash.Write([]byte("cramershoup_secret"))
	var out [56]byte //is it ok? use 64 instead?
	hash.Read(out[:])
	return ed448.NewDecafScalar(out[:]) //check the decoding
}
