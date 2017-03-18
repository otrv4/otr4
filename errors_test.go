package otr4

import (
	. "gopkg.in/check.v1"
)

func (s *OTR4Suite) Test_NewOTRError(c *C) {
	err := newOtrError("new error")
	c.Assert(err, ErrorMatches, ".* new error")
}

func (s *OTR4Suite) Test_ReturnFirstError(c *C) {
	err1 := newOtrError("new error 1")
	err2 := newOtrError("new error 2")

	err := firstError(err1, err2)

	c.Assert(err, ErrorMatches, ".* new error 1")
}
