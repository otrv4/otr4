package otr4

import (
	"math/big"
	"strconv"

	"github.com/twstrike/ed448"
	"golang.org/x/crypto/sha3"
)

func hashToScalar(in []byte) ed448.Scalar {
	hash := make([]byte, fieldBytes)
	sha3.ShakeSum256(hash, in)
	s := ed448.NewScalar(hash)
	return s
}

func appendBytes(bs ...interface{}) []byte {
	var b []byte

	if len(bs) < 2 {
		panic("programmer error: missing append arguments")
	}

	for _, e := range bs {
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

func appendAndHash(bs ...interface{}) ed448.Scalar {
	return hashToScalar(appendBytes(bs...))
}

func appendWord32(b []byte, data uint32) []byte {
	return append(b, byte(data>>24), byte(data>>16), byte(data>>8), byte(data))
}

func appendWord64(b []byte, data int64) []byte {
	return append(b, byte(data>>56), byte(data>>48), byte(data>>40), byte(data>>32), byte(data>>24), byte(data>>16), byte(data>>8), byte(data))
}

func appendData(b, data []byte) []byte {
	return append(appendWord32(b, uint32(len(data))), data...)
}

func appendMPI(b []byte, data *big.Int) []byte {
	return appendData(b, data.Bytes())
}

func appendPoint(b []byte, p ed448.Point) []byte {
	return append(b, p.Encode()...)
}

func appendSignature(bs []byte, data interface{}) []byte {
	switch d := data.(type) {
	case *signature:
		b := serializeSignature(d)
		return append(bs, b[:]...)
	case *dsaSignature:
		var b [dsaSigBytes]byte
		copy(b[:], d[:])
		return append(bs, b[:]...)
	}
	return nil
}

func extractWord32(bs []byte) ([]byte, uint32, bool) {
	if len(bs) < 4 {
		return nil, 0, false
	}

	return bs[4:], uint32(bs[0])<<24 |
		uint32(bs[1])<<16 |
		uint32(bs[2])<<8 |
		uint32(bs[3]), true
}

func extractWord64(bs []byte) ([]byte, uint64, bool) {
	if len(bs) < 4 {
		return nil, 0, false
	}

	return bs[4:], uint64(bs[0])<<56 |
		uint64(bs[1])<<48 |
		uint64(bs[2])<<40 |
		uint64(bs[3])<<32 |
		uint64(bs[4])<<24 |
		uint64(bs[5])<<16 |
		uint64(bs[6])<<8 |
		uint64(bs[7]), true
}

func extractData(bs []byte) ([]byte, []byte, bool) {
	cursor, l, ok := extractWord32(bs)
	if !ok || len(cursor) < int(l) {
		return bs, nil, false
	}

	data := cursor[:int(l)]
	cursor = cursor[int(l):]
	return cursor, data, ok
}

func extractPoint(b []byte, cursor int) (ed448.Point, int, error) {
	if len(b) < 56 {
		return nil, 0, errInvalidLength
	}

	p := ed448.NewPointFromBytes()
	valid, err := p.Decode(b[cursor:cursor+fieldBytes], false)
	if !valid {
		return nil, 0, err
	}

	cursor += fieldBytes

	return p, cursor, err
}

func fromHexChar(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}

	return 0, false
}

func parseToByte(str string) []byte {
	var bs []byte

	for _, s := range str {
		l, valid := fromHexChar(byte(s))
		if !valid {
			return nil
		}
		bs = append(bs, l)
	}

	return bs
}

func bytesToString(bs []byte) string {
	var str string
	for _, i := range bs {
		str += strconv.Itoa(int(i))
	}

	return str
}
