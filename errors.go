package otr4

import "fmt"

var errInvalidPublicKey = newOtrError("not a valid public key")
var notEnoughEntropy = newOtrError("cannot source enough entropy")
var errImpossibleToDecrypt = newOtrError("cannot decrypt the message")

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
