package otr4

type publicKey struct{}

type secretKey struct{}

func generateSecretKey() (*secretKey, bool) {
	return &secretKey{}, true
}

func generatePublicKey() (*publicKey, bool) {
	return &publicKey{}, true
}
