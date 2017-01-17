package otr4

import (
	"math/big"
)

type publicKey struct {
	pub *big.Int
}

type secretKey struct {
	sec *big.Int
}

func generateSecretKey() (*secretKey, bool) {
	return &secretKey{}, true
}

func generatePublicKey() (*publicKey, bool) {
	return &publicKey{}, true
}
