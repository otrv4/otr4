package otr4

import (
	"bytes"
	"encoding/binary"
	"strings"
)

type signature [112]byte

type dsaSignature [40]byte

type userProfile struct {
	versions        string
	pubKey          *cramerShoupPublicKey
	expiration      uint64
	sig             *signature
	transitionalSig *dsaSignature
}

// XXX: include the other params
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

// XXX: make this append?
func serializeSig(sig *signature) []byte {
	var binBuf bytes.Buffer

	binary.Write(&binBuf, binary.BigEndian, sig)

	return binBuf.Bytes()
}

func serializeTransitionalSig(sig *dsaSignature) []byte {
	var binBuf bytes.Buffer

	binary.Write(&binBuf, binary.BigEndian, sig)

	return binBuf.Bytes()
}

func serializeBody(profile *userProfile) []byte {
	var out []byte

	out = appendData(out, parseToByte(profile.versions))
	out = append(out, profile.pubKey.serialize()...)
	out = appendWord64(out, profile.expiration)

	return out
}

//XXX: this will be the signed verson.
func (profile *userProfile) serialize() []byte {
	var out []byte

	out = appendData(out, parseToByte(profile.versions))
	out = append(out, profile.pubKey.serialize()...)
	out = appendWord64(out, profile.expiration)
	out = append(out, serializeSig(profile.sig)...)
	out = append(out, serializeTransitionalSig(profile.transitionalSig)...)

	return out
}
