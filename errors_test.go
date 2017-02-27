package otr4

import (
	. "gopkg.in/check.v1"
)

func (s *OTR4Suite) Test_NewOTRError(c *C) {
	e := newOtrError("new error")
	c.Assert(e, ErrorMatches, ".* new error")
}
