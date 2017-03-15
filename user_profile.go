package otr4

import (
	"bytes"
	"math/big"
)

type signature [112]byte

type userProfile struct {
	versions        []byte // XXX: for the moment, use string?
	pubKey          *cramerShoupPublicKey
	expiration      uint64
	sig             signature
	transitionalSig *big.Int // XXX: for the moment, use MPI?
}

func newProfile(v []byte) (*userProfile, error) {
	if len(v) == 0 {
		return nil, errInvalidVersion
	}

	// XXX: should the error be 'not supported'?
	v1, v2 := []byte{0x01}, []byte{0x02}
	if bytes.Contains(v, v1) || bytes.Contains(v, v2) {
		return nil, errInvalidVersion
	}
	profile := &userProfile{versions: v}

	return profile, nil
}
