package otr4

import (
	"github.com/twstrike/ed448"
	"golang.org/x/crypto/sha3"
)

func auth(aPub, bPub, bPubEcdh *publicKey, aSec *secretKey, message []byte) (sigma [6]ed448.BigNumber) {
	return
}

func hashToScalar(in []byte) (scalar ed448.BigNumber) {
	hash := sha3.Sum512(in)
	hashSlice := hash[0:64]
	scalar = ed448.DeserializeModQ(hashSlice)
	return
}
