package otr4

import (
	"math/big"
	"strings"
)

type signature [112]byte

type userProfile struct {
	versions        string
	pubKey          *cramerShoupPublicKey
	expiration      uint64
	sig             signature
	transitionalSig *big.Int // XXX: for the moment, use MPI?
}

func newProfile(v string) (*userProfile, error) {
	if len(v) == 0 {
		return nil, errInvalidVersion
	}

	v1, v2 := "1", "2"
	if strings.Contains(v, v1) || strings.Contains(v, v2) {
		return nil, errInvalidVersion
	}
	profile := &userProfile{versions: v}

	return profile, nil
}
