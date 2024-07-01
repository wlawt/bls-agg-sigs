package main

import (
	"fmt"

	"github.com/prysmaticlabs/prysm/v5/crypto/bls/blst"
	"github.com/prysmaticlabs/prysm/v5/crypto/bls/common"
)

func main() {
	var sigs []common.Signature
	k1, _ := blst.RandKey()
	k2, _ := blst.RandKey()
	msg1 := [32]byte{0x1}
	msg2 := [32]byte{0x1, 0x2}
	sigs = append(sigs, k1.Sign(msg1[:]))
	sigs = append(sigs, k2.Sign(msg2[:]))
	// 1. Aggregate first set of signatures
	agg12 := blst.AggregateSignatures(sigs)

	// 2. Build more
	k3, _ := blst.RandKey()
	msg3 := [32]byte{0x1, 0x2, 0x3}

	// 3. Aggregate signature with an already AggregatedSig
	agg123 := blst.AggregateSignatures([]common.Signature{agg12, k3.Sign(msg3[:])})

	// Build more again
	sigs = []common.Signature{}
	k4, _ := blst.RandKey()
	k5, _ := blst.RandKey()
	msg4 := [32]byte{0x1, 0x2, 0x3, 0x4}
	msg5 := [32]byte{0x1, 0x2, 0x3, 0x4, 0x5}
	sigs = append(sigs, k4.Sign(msg4[:]))
	sigs = append(sigs, k5.Sign(msg5[:]))
	// Aggregate another set
	agg45 := blst.AggregateSignatures(sigs)

	// Doing step 3 again
	agg12345 := blst.AggregateSignatures([]common.Signature{agg123, agg45})

	// Verify
	var msgs [][32]byte
	msgs = append(msgs, msg1)
	msgs = append(msgs, msg2)
	msgs = append(msgs, msg3)
	msgs = append(msgs, msg4)
	msgs = append(msgs, msg5)
	v := agg12345.AggregateVerify([]common.PublicKey{k1.PublicKey(), k2.PublicKey(), k3.PublicKey(), k4.PublicKey(), k5.PublicKey()}, msgs)
	if !v {
		fmt.Println("v not valid")
	} else {
		fmt.Println("v valid")
	}
}
