package otr4

import (
	"github.com/twstrike/ed448"

	. "gopkg.in/check.v1"
)

func (s *OTR4Suite) Test_HashToScalar(c *C) {
	scalar := hashToScalar(testByteSlice)

	exp := ed448.NewScalar([]byte{
		0x1e, 0xda, 0x47, 0xce, 0x5a, 0x2a, 0x10, 0xdb,
		0x67, 0x8a, 0x38, 0x2c, 0xe2, 0x70, 0x2f, 0xea,
		0x92, 0x8d, 0x6a, 0x4c, 0x11, 0x27, 0xfd, 0x7c,
		0xb0, 0x6f, 0x1a, 0x0b, 0x71, 0x82, 0x6b, 0x90,
		0xe3, 0x6b, 0xdd, 0x7d, 0x17, 0xab, 0xfd, 0x9e,
		0xad, 0xf2, 0x04, 0x0d, 0x97, 0x19, 0x46, 0x09,
		0x3d, 0xb3, 0xa3, 0x67, 0xca, 0x01, 0x8d, 0x95,
	})

	c.Assert(scalar, DeepEquals, exp)
}

func (s *OTR4Suite) Test_AppendBytes(c *C) {
	empty := []byte{}
	bytes := []byte{
		0x04, 0x2a, 0xf3, 0xcc, 0x69, 0xbb, 0xa1, 0x50,
	}

	exp := []byte{
		0x04, 0x2a, 0xf3, 0xcc, 0x69, 0xbb, 0xa1, 0x50,
		0xa3, 0xf8, 0x0e, 0xb2, 0xa6, 0x99, 0x23, 0x9a,
		0x81, 0x9b, 0x5e, 0xc3, 0x30, 0xce, 0xd7, 0x49,
		0x7b, 0xdb, 0x3b, 0xe7, 0x0d, 0xd0, 0x91, 0xec,
		0x6e, 0xc6, 0xd7, 0xdc, 0xd1, 0xd3, 0xe2, 0x68,
		0xd5, 0xf1, 0xcc, 0xd6, 0x2f, 0x87, 0xb0, 0x27,
		0xd7, 0x59, 0x89, 0x65, 0x02, 0x16, 0xec, 0x5a,
		0x0f, 0x84, 0x1a, 0xbe, 0xda, 0xa1, 0x88, 0x02,
		0xd8, 0x8c, 0xc8, 0xae, 0x88, 0xeb, 0xcb, 0xbd,
		0x73, 0xcc, 0x8c, 0x4c, 0x87, 0xc8, 0xd8, 0x0d,
		0x27, 0x7e, 0xb3, 0xd8, 0xe1, 0x1d, 0x55, 0x35,
		0xdf, 0x42, 0x38, 0xf2, 0x4f, 0x65, 0xf5, 0x31,
		0xc1, 0x35, 0x3b, 0x6a, 0x3a, 0x0a, 0x7b, 0x3b,
		0x6d, 0x4c, 0x6e, 0xd7, 0xfc, 0x53, 0xa0, 0x3b,
		0xba, 0xfe, 0xda, 0x5b, 0xd1, 0x63, 0x8d, 0x3a,
	}

	c.Assert(func() { appendBytes() }, Panics, "programmer error: missing append arguments")
	c.Assert(func() { appendBytes(bytes) }, Panics, "programmer error: missing append arguments")
	c.Assert(func() { appendBytes("not a valid input", bytes) }, Panics, "programmer error: invalid input")
	c.Assert(appendBytes(empty, bytes, testPrivA.z, testPubA.h), DeepEquals, exp)
}

func (s *OTR4Suite) Test_AppendAndHash(c *C) {
	hash := appendAndHash(testPrivA.z, testPubA.h)

	expScalar := ed448.NewScalar([]byte{
		0x7f, 0xdb, 0x06, 0x43, 0xaa, 0x7e, 0x65, 0xa0,
		0x4f, 0x82, 0x2e, 0x18, 0xdd, 0x45, 0xf1, 0x80,
		0x88, 0x49, 0x58, 0xfb, 0x50, 0x39, 0x3e, 0x56,
		0x04, 0x09, 0x40, 0x23, 0xd4, 0x47, 0xc9, 0x7c,
		0x22, 0x4e, 0x41, 0x78, 0x65, 0xbb, 0x9e, 0x11,
		0x60, 0xe0, 0xbe, 0xb4, 0x42, 0x32, 0xa0, 0x54,
		0x9c, 0xe6, 0xa, 0x96, 0x38, 0x83, 0x4a, 0x19})

	c.Assert(hash, DeepEquals, expScalar)
}

func (s *OTR4Suite) Test_ParsingOfScalar(c *C) {
	bytes := []byte{
		0x04, 0x2a, 0xf3, 0xcc, 0x69, 0xbb, 0xa1, 0x50,
		0xa3, 0xf8, 0x0e, 0xb2, 0xa6, 0x99, 0x23, 0x9a,
		0x81, 0x9b, 0x5e, 0xc3, 0x30, 0xce, 0xd7, 0x49,
		0x7b, 0xdb, 0x3b, 0xe7, 0x0d, 0xd0, 0x91, 0xec,
		0x6e, 0xc6, 0xd7, 0xdc, 0xd1, 0xd3, 0xe2, 0x68,
		0xd5, 0xf1, 0xcc, 0xd6, 0x2f, 0x87, 0xb0, 0x27,
		0xd7, 0x59, 0x89, 0x65, 0x02, 0x16, 0xec, 0x5a,
	}
	scalars := parseScalar(bytes[:])

	expScalars := []ed448.Scalar{ed448.NewScalar([]byte{
		0x11, 0xe5, 0x9a, 0x21, 0xd7, 0xf8, 0x28, 0x2d,
		0x4e, 0x69, 0x49, 0x24, 0x34, 0xd7, 0xb6, 0x78,
		0xf1, 0x64, 0x88, 0x14, 0xe7, 0xf2, 0x88, 0x85,
		0x91, 0xb7, 0x71, 0x6a, 0x0e, 0xd0, 0x91, 0xec,
		0x6e, 0xc6, 0xd7, 0xdc, 0xd1, 0xd3, 0xe2, 0x68,
		0xd5, 0xf1, 0xcc, 0xd6, 0x2f, 0x87, 0xb0, 0x27,
		0xd7, 0x59, 0x89, 0x65, 0x2, 0x16, 0xec, 0x1a})}

	c.Assert(scalars, DeepEquals, expScalars)
}
