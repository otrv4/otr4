package otr4

import (
	"math/big"

	. "gopkg.in/check.v1"
)

func (s *OTR4Suite) Test_ValidationOfDHGroupElement(c *C) {
	//less than two
	valid := isGroupElement(big.NewInt(0))
	c.Assert(valid, Equals, false)

	valid = isGroupElement(big.NewInt(1))
	c.Assert(valid, Equals, false)

	valid = isGroupElement(big.NewInt(-1))
	c.Assert(valid, Equals, false)

	// greater than modulos minus two
	valid = isGroupElement(sub(p, big.NewInt(2)))
	c.Assert(valid, Equals, true)

	valid = isGroupElement(sub(p, big.NewInt(3)))
	c.Assert(valid, Equals, true)

	valid = isGroupElement(add(p, big.NewInt(1)))
	c.Assert(valid, Equals, false)

	// equal to two
	valid = isGroupElement(big.NewInt(2))
	c.Assert(valid, Equals, true)
}
