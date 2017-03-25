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
	transitionalSig *dsaSignature
	sig             *signature
}

// XXX: make this not a method of conversation
// XXX: add tranSignature
func (c *conversation) newProfile(v string, keyPair *cramerShoupKeyPair) (*userProfile, error) {
	profile, err := createProfileBody(v, keyPair)
	if err != nil {
		return nil, err
	}

	err = profile.sign(c.rand(), keyPair)
	if err != nil {
		return nil, err
	}

	return profile, nil
}

// XXX: add tranSignature
func createProfileBody(v string, keyPair *cramerShoupKeyPair) (*userProfile, error) {
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
		pub:        keyPair.pub,
		expiration: t,
		sig:        &signature{},
	}

	return profile, nil
}

func (profile *userProfile) sign(rand io.Reader, keyPair *cramerShoupKeyPair) error {

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

func serializeSignature(data *signature) [112]byte {
	var b [112]byte
	copy(b[:], data[:])

	return b
}

func deserializeSignature(bs []byte) *signature {
	sig := &signature{}

	for i, b := range bs {
		sig[i] = b
	}
	return sig
}

func deserializeTransSignature(bs []byte) *dsaSignature {
	sig := &dsaSignature{}

	for i, b := range bs {
		sig[i] = b
	}
	return sig
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

func (profile *userProfile) serialize() []byte {
	var out []byte

	out = serializeBody(profile)
	out = appendSignature(out, profile.sig)

	return out
}

func deserializeProfile(ser []byte) *userProfile {
	var err error

	profile := &userProfile{}

	// XXX: make those numbers not magical
	// XXX:do not ignore errors?
	cursor := 6
	_, rslt, _ := extractData(ser[:cursor])

	profile.versions = bytesToString(rslt)

	profile.pub, err = deserialize(ser[cursor : cursor+170])
	if err != nil {
		return nil
	}
	_, expiration, _ := extractWord64(ser[cursor+170 : cursor+170+8])

	profile.expiration = int64(expiration)
	profile.transitionalSig = deserializeTransSignature(ser[184:224])
	profile.sig = deserializeSignature(ser[224:])

	return profile
}
