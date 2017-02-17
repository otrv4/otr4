package otr4

import "fmt"

var errInvalidPublicKey = newOtrError("not a valid Public Key")
var errShortRandomReader = newOtrError("not enough bytes")

type otrError struct {
	msg string
}

func newOtrError(s string) error {
	return otrError{msg: s}
}

func newOtrErrorf(format string, a ...interface{}) error {
	return otrError{msg: fmt.Sprintf(format, a...)}
}

func (oe otrError) Error() string {
	return "otr: " + oe.msg
}
