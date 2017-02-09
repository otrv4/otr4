package otr4

import (
	"github.com/twstrike/ed448"
	"golang.org/x/crypto/sha3"
)

var (
	primeOrder = []byte{
		0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78,
		0x23, 0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2,
		0x6c, 0x21, 0x90, 0x36, 0xd6, 0xae, 0x49,
		0xdb, 0x4e, 0xc4, 0xe9, 0x23, 0xca, 0x7c,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
	}

	basePoint = ed448.NewPoint(
		[16]uint32{
			0xffffffe, 0xfffffff, 0xfffffff, 0xfffffff,
			0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff,
			0x0000003, 0x0000000, 0x0000000, 0x0000000,
			0x0000000, 0x0000000, 0x0000000, 0x0000000,
		},
		[16]uint32{
			0xf752992, 0x81e6d37, 0x1c28721, 0x3078ead,
			0x394666c, 0x135cfd2, 0x0506061, 0x41149c5,
			0xf5490b3, 0x31d30e4, 0x90dc141, 0x9020149,
			0x4c1e328, 0x52341b0, 0x3c10a1b, 0x1423785,
		},
		[16]uint32{
			0xffffffb, 0xfffffff, 0xfffffff, 0xfffffff,
			0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff,
			0xffffffe, 0xfffffff, 0xfffffff, 0xfffffff,
			0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff,
		},
		[16]uint32{
			0x0660415, 0x8f205b7, 0xfd3824f, 0x881c60c,
			0xd08500d, 0x377a638, 0x4672615, 0x8c66d5d,
			0x8e08e13, 0xe52fa55, 0x1b6983d, 0x87770ae,
			0xa0aa7ff, 0x4388f55, 0x5cf1a91, 0xb4d9a78,
		},
	)
)

//TODO
func auth(rand func() []ed448.Scalar, ourPub, theirPub, theirPubEcdh ed448.Point, ourSec ed448.Scalar, message []byte) []byte {
	a := rand()
	t1, c2, c3, r2, r3 := a[0], a[1], a[2], a[3], a[4]
	pt1 := ed448.PointScalarMul(basePoint, t1)
	pt2 := ed448.DoubleScalarMul(basePoint, theirPub, r2, c2)
	pt3 := ed448.DoubleScalarMul(basePoint, theirPubEcdh, r3, c3)
	values := concat(basePoint.Encode(), primeOrder, ourPub.Encode(),
		theirPub.Encode(), theirPubEcdh.Encode(), pt1.Encode(), pt2.Encode(), pt3.Encode(), message)
	c := hashToScalar(values)
	c1, r1 := ed448.NewDecafScalar([56]byte{}), ed448.NewDecafScalar([56]byte{})
	c1.Sub(c, c2)
	c1.Sub(c1, c3)
	r1.Mul(c1, ourSec)
	r1.Sub(t1, r1)
	sigma := concat(c1.Encode(), r1.Encode(), c2.Encode(), r2.Encode(), c3.Encode(), r3.Encode())
	return sigma
}

func hashToScalar(in []byte) ed448.Scalar {
	hash := make([]byte, 56)
	sha3.ShakeSum256(hash, in)
	s := ed448.NewDecafScalar([56]byte{})
	s.Decode(hash)
	return s
}

func concat(bytes ...[]byte) []byte {
	b := []byte{}
	if len(bytes) < 2 {
		panic("missing concat arguments")
	}
	for i := range bytes {
		b = append(b, bytes[i]...)
	}

	return b
}
