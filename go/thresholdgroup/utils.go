package thresholdgroup

import (
	"fmt"

	"github.com/dfinity/go-dfinity-crypto/bls"
)

func Sign(message string) {
	bls.Init(bls.CurveSNARK)

	var sec bls.SecretKey
	sec.SetByCSPRNG()

	pub := sec.GetPublicKey()

	fmt.Printf("Public key: %v\n", pub)

	sign := sec.Sign(message)

	if !sign.Verify(pub, message) {
		fmt.Printf("Signature does not verify\n")
	}

	fmt.Printf("Signature: %v\n", sign)
}
