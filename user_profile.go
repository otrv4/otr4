package otr4

import (
	"io"
	"strings"
	"time"

	"github.com/twstrike/ed448"
)

type signature [sigBytes]byte

type dsaSignature [dsaSigBytes]byte

type userProfile struct {
	versions        string
	pub             *cramerShoupPublicKey
	expiration      int64
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

	t := time.Now().Unix() + int64(1209600)

	profile := &userProfile{
		versions:   v,
		expiration: t,
		sig:        &signature{},
	}

	return profile, nil
}

func serializeSignature(data *signature) [112]byte {
	var b [112]byte
	copy(b[:], data[:])

	return b
}

func serializeBody(profile *userProfile) []byte {
	var out []byte

	out = appendData(out, parseToByte(profile.versions))
	out = appendBytes(out, profile.pub.serialize())
	out = appendWord64(out, profile.expiration)

	if profile.transitionalSig != nil {
		out = appendSignature(out, profile.transitionalSig)
	}

	return out
}

func (profile *userProfile) sign(rand io.Reader, keyPair *cramerShoupKeyPair) error {
	profile.pub = keyPair.pub

	sym, err := randSymKey(rand)
	if err != nil {
		// XXX: set profile to nil?
		return err
	}

	var k []byte
	k = appendBytes(k, keyPair.priv.z.Encode())
	k = appendBytes(k, keyPair.pub.h.Encode())
	k = appendBytes(k, sym)

	var key [144]byte
	copy(key[:], k)

	c := ed448.NewDecafCurve()
	body := serializeBody(profile)

	sig, valid := c.Sign(key, body)
	if !valid {
		return errCorruptEncryptedSignature
	}

	for i, b := range sig {
		profile.sig[i] = b
	}

	return nil
}

func (profile *userProfile) verify(pub *cramerShoupPublicKey) (bool, error) {
	c := ed448.NewDecafCurve()
	body := serializeBody(profile)

	var pubKey [fieldBytes]byte
	copy(pubKey[:], pub.h.Encode())

	valid, err := c.Verify(serializeSignature(profile.sig), body, pubKey)
	if err != nil {
		return valid, err
	}

	return valid, nil
}

//XXX: this will be the signed version.
// just call ser body?
func (profile *userProfile) serialize() []byte {
	var out []byte

	out = appendData(out, parseToByte(profile.versions))
	out = appendBytes(out, profile.pub.serialize())
	out = appendWord64(out, profile.expiration)
	out = appendSignature(out, profile.sig)
	out = appendSignature(out, profile.transitionalSig)

	return out
}
