package otr4

import (
	"math/big"

	"github.com/twstrike/ed448"
	"golang.org/x/crypto/sha3"
)

func hashToScalar(in []byte) ed448.Scalar {
	hash := make([]byte, fieldBytes)
	sha3.ShakeSum256(hash, in)
	s := ed448.NewScalar(hash)
	return s
}

func appendBytes(bytes ...interface{}) (b []byte) {
	if len(bytes) < 2 {
		panic("programmer error: missing append arguments")
	}

	for _, e := range bytes {
		switch i := e.(type) {
		case ed448.Point:
			b = append(b, i.Encode()...)
		case ed448.Scalar:
			b = append(b, i.Encode()...)
		case []byte:
			b = append(b, i...)
		default:
			panic("programmer error: invalid input")
		}
	}
	return b
}

func appendAndHash(bytes ...interface{}) ed448.Scalar {
	return hashToScalar(appendBytes(bytes...))
}

func appendWord32(bytes []byte, data uint32) []byte {
	return append(bytes, byte(data>>24), byte(data>>16), byte(data>>8), byte(data))
}

// XXX: refactor
func appendWord64(bytes []byte, data uint64) []byte {
	return append(bytes, byte(data>>56), byte(data>>48), byte(data>>40), byte(data>>32), byte(data>>24), byte(data>>16), byte(data>>8), byte(data))
}

func appendData(bytes, data []byte) []byte {
	return append(appendWord32(bytes, uint32(len(data))), data...)
}

func appendMPI(bytes []byte, data *big.Int) []byte {
	return appendData(bytes, data.Bytes())
}

func appendPoint(bytes []byte, p ed448.Point) []byte {
	return append(bytes, p.Encode()...)
}

func extractPoint(bytes []byte, cursor int) (ed448.Point, int, error) {
	if len(bytes) < 56 {
		return nil, 0, errInvalidLength
	}

	p := ed448.NewPointFromBytes()
	valid, err := p.Decode(bytes[cursor:cursor+fieldBytes], false)
	if !valid {
		return nil, 0, err
	}

	cursor += fieldBytes

	return p, cursor, err
}
