package otr4

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"

	"github.com/twstrike/ed448"
)

type signature [sigBytes]byte

type dsaSignature [dsaSigBytes]byte

type userProfile struct {
	versions        string
	pub             *cramerShoupPublicKey
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

func appendSig(b []byte, sig *signature) []byte {
	var binBuf bytes.Buffer

	binary.Write(&binBuf, binary.BigEndian, sig)
	return append(b, binBuf.Bytes()...)
}

func appendTransitionalSig(b []byte, sig *dsaSignature) []byte {
	var binBuf bytes.Buffer

	binary.Write(&binBuf, binary.BigEndian, sig)

	return append(b, binBuf.Bytes()...)
}

func serializeBody(profile *userProfile) []byte {
	var out []byte

	out = appendData(out, parseToByte(profile.versions))
	out = append(out, profile.pub.serialize()...)
	out = appendWord64(out, profile.expiration)

	return out
}

//XXX: this will be the signed verson.
func (profile *userProfile) serialize() []byte {
	var out []byte

	out = appendData(out, parseToByte(profile.versions))
	out = append(out, profile.pub.serialize()...)
	out = appendWord64(out, profile.expiration)
	out = appendSig(out, profile.sig)
	out = appendTransitionalSig(out, profile.transitionalSig)

	return out
}
