package otr4

import (
	"io"

	"github.com/twstrike/ed448"

	"golang.org/x/crypto/sha3"
)

type keyPair struct {
	pub  publicKey
	priv privateKey
}

// XXX: change names
type publicKey struct {
	h ed448.Point
}

type privateKey struct {
	r ed448.Scalar
}

func isValidPublicKey(pubs ...*publicKey) bool {
	for _, pub := range pubs {
		if !(pub.h.IsOnCurve()) {
			return false
		}
	}
	return true
}

// XXX: encode the priv as SCALAR
func generateKeys(rand io.Reader) (*publicKey, *privateKey, error) {
	pub := &publicKey{}
	priv := &privateKey{}

	privateKey := make([]byte, privateKeySize)
	_, err := io.ReadFull(rand, privateKey[:])
	if err != nil {
		return nil, nil, err
	}

	digest := make([]byte, privateKeySize)
	sha3.ShakeSum256(digest, privateKey)

	digest[0] &= -(ed448.Cofactor)
	digest[privateKeySize-1] = 0
	digest[privateKeySize-2] |= mask

	priv.r = ed448.NewScalar(digest[:])
	for c := uint(1); c < uint(ed448.Cofactor); c <<= 1 {
		priv.r.Halve(priv.r)
	}

	pub.h = ed448.PrecomputedScalarMul(priv.r)

	return pub, priv, nil
}

var pubKeyType = []byte{0x00, 0x10}
var pubKeyTypeValue = uint16(0x0010)

func (pub *publicKey) serialize() []byte {
	if pub.h == nil {
		return nil
	}

	rslt := pubKeyType
	rslt = appendPoint(rslt, pub.h)
	return rslt
}

func deserialize(ser []byte) (*publicKey, error) {
	pub := &publicKey{}
	if len(ser) < 58 {
		return nil, errInvalidLength
	}

	var err error
	cursor := 2
	pub.h, cursor, err = extractPoint(ser, cursor)

	return pub, err
}
