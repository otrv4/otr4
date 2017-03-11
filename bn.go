package otr4

import "math/big"

func add(l, r *big.Int) *big.Int {
	return new(big.Int).Add(l, r)
}

func sub(l, r *big.Int) *big.Int {
	return new(big.Int).Sub(l, r)
}

func lessOrEqual(l, r *big.Int) bool {
	return l.Cmp(r) != 1
}

func greatOrEqual(l, r *big.Int) bool {
	return l.Cmp(r) != -1
}
