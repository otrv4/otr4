package otr4

import (
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/twstrike/ed448"
)

func randScalar(r io.Reader) (ed448.Scalar, error) {
	b := make([]byte, fieldBytes)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return nil, notEnoughEntropy
	}
	return ed448.NewDecafScalar(b), nil
}

func randLongTermScalar(r io.Reader) (ed448.Scalar, error) {
	b := make([]byte, fieldBytes)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return nil, notEnoughEntropy
	}
	hash := sha3.NewShake256()
	hash.Write(b)
	hash.Write([]byte("cramershoup_secret"))
	var out [fieldBytes]byte
	hash.Read(out[:])
	return ed448.NewDecafScalar(out[:]), nil
}
