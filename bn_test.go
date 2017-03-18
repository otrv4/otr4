package otr4

import (
	"math/big"

	. "gopkg.in/check.v1"
)

func (s *OTR4Suite) Test_BigIntAddition(c *C) {
	result := add(big.NewInt(7), big.NewInt(3))
	c.Assert(result, DeepEquals, big.NewInt(10))

	result = add(big.NewInt(0), big.NewInt(0))
	c.Assert(result, DeepEquals, big.NewInt(0))
}

func (s *OTR4Suite) Test_BigIntSubtraction(c *C) {
	// XXX: this fails when the result is zero
	result := sub(big.NewInt(7), big.NewInt(3))
	c.Assert(result, DeepEquals, big.NewInt(4))
}

func (s *OTR4Suite) Test_BigIntLessOrEqualThan(c *C) {
	result := lessOrEqual(big.NewInt(7), big.NewInt(13))
	c.Assert(result, Equals, true)

	result = lessOrEqual(big.NewInt(7), big.NewInt(7))
	c.Assert(result, Equals, true)

	result = lessOrEqual(big.NewInt(7), big.NewInt(3))
	c.Assert(result, Equals, false)
}

func (s *OTR4Suite) Test_BigIntGreatOrEqualThan(c *C) {
	result := greatOrEqual(big.NewInt(7), big.NewInt(3))
	c.Assert(result, Equals, true)

	result = greatOrEqual(big.NewInt(7), big.NewInt(7))
	c.Assert(result, Equals, true)

	result = greatOrEqual(big.NewInt(3), big.NewInt(7))
	c.Assert(result, Equals, false)
}
