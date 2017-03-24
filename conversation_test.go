package otr4

import (
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type OTR4Suite struct{}

var _ = Suite(&OTR4Suite{})
