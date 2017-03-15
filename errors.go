package otr4

var errInvalidPublicKey = newOtrError("not a valid public key")
var notEnoughEntropy = newOtrError("cannot source enough entropy")
var errImpossibleToDecrypt = newOtrError("cannot decrypt the message")
var errInvalidVersion = newOtrError("no valid version agreement could be found")

type otrError struct {
	msg string
}

func newOtrError(s string) error {
	return otrError{msg: s}
}

func (oe otrError) Error() string {
	return "otr: " + oe.msg
}
