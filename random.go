package otr4

import (
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/twstrike/ed448"
)

func randInto(r io.Reader, b []byte) error {
	_, err := io.ReadFull(r, b)

	if err != nil {
		return errShortRandomReader
	}
	return nil
}

func randScalar(r io.Reader, b []byte) (ed448.Scalar, error) {
	_, err := io.ReadFull(r, b)

	if err != nil {
		return nil, errShortRandomReader
	}

	return ed448.NewDecafScalar(b), nil
}

func randLongTermScalar(r io.Reader) ed448.Scalar {
	b := make([]byte, fieldBytes)
	err := randInto(r, b)

	if err != nil {
		return nil
	}

	hash := sha3.NewShake256()
	hash.Write(b)
	hash.Write([]byte("cramershoup_secret"))

	var out [fieldBytes]byte
	hash.Read(out[:])

	return ed448.NewDecafScalar(out[:])
}
