package otr4

type signatureKey [keySigBytes]byte

func (k *signatureKey) secretKey() []byte {
	return k[:fieldBytes]
}

func (k *signatureKey) publicKey() []byte {
	return k[fieldBytes : 2*fieldBytes]
}

func (k *signatureKey) symKey() []byte {
	return k[2*fieldBytes:]
}

func (k *signatureKey) bytes() [keySigBytes]byte {
	var out [keySigBytes]byte
	copy(out[:], k[:])
	return out
}
