package result

import (
	"fmt"

	"github.com/keep-network/keep-core/pkg/operator"

	relayChain "github.com/keep-network/keep-core/pkg/beacon/relay/chain"
	"github.com/keep-network/keep-core/pkg/beacon/relay/gjkr"
	"github.com/keep-network/keep-core/pkg/beacon/relay/member"
	"github.com/keep-network/keep-core/pkg/chain"
)

// SigningMember represents a member sharing preferred DKG result hash
// and signature over this hash with peer members.
type SigningMember struct {
	index member.Index

	// Key used for signing the DKG result hash.
	privateKey *operator.PrivateKey

	// Hash of DKG result preferred by the current participant.
	preferredDKGResultHash relayChain.DKGResultHash
	// Signature over preferredDKGResultHash calculated by the member.
	selfDKGResultSignature operator.Signature
}

// NewSigningMember creates a member to execute signing DKG result hash.
func NewSigningMember(
	memberIndex gjkr.MemberID,
	operatorPrivateKey *operator.PrivateKey,
) *SigningMember {
	return &SigningMember{
		index:      memberIndex,
		privateKey: operatorPrivateKey,
	}
}

// SignDKGResult calculates hash of DKG result and member's signature over this
// hash. It packs the hash and signature into a broadcast message.
//
// See Phase 13 of the protocol specification.
func (sm *SigningMember) SignDKGResult(
	dkgResult *relayChain.DKGResult,
	chainHandle chain.Handle,
) (
	*DKGResultHashSignatureMessage,
	error,
) {
	resultHash, err := chainHandle.ThresholdRelay().CalculateDKGResultHash(dkgResult)
	if err != nil {
		return nil, fmt.Errorf("dkg result hash calculation failed [%v]", err)
	}
	sm.preferredDKGResultHash = resultHash

	signature, err := operator.Sign(resultHash[:], sm.privateKey)
	if err != nil {
		return nil, fmt.Errorf("dkg result hash signing failed [%v]", err)
	}

	// Register self signature.
	sm.selfDKGResultSignature = signature

	return &DKGResultHashSignatureMessage{
		senderIndex: sm.index,
		resultHash:  resultHash,
		signature:   signature,
		publicKey:   &sm.privateKey.PublicKey,
	}, nil
}

// VerifyDKGResultSignatures verifies signatures received in messages from other
// group members.
//
// It collects signatures supporting only the same DKG result hash as the one
// preferred by the current member.
//
// Each member is allowed to broadcast only one signature over a preferred DKG
// result hash.
//
// See Phase 13 of the protocol specification.
func (sm *SigningMember) VerifyDKGResultSignatures(
	messages []*DKGResultHashSignatureMessage,
) (map[member.Index]operator.Signature, error) {
	duplicatedMessagesFromSender := func(senderIndex member.Index) bool {
		messageFromSenderAlreadySeen := false
		for _, message := range messages {
			if message.senderIndex == senderIndex {
				if messageFromSenderAlreadySeen {
					return true
				}
				messageFromSenderAlreadySeen = true
			}
		}
		return false
	}

	receivedValidResultSignatures := make(map[member.Index]operator.Signature)

	for _, message := range messages {
		// Check if message from self.
		if message.senderIndex == sm.index {
			continue
		}

		// Check if sender sent multiple messages.
		if duplicatedMessagesFromSender(message.senderIndex) {
			fmt.Printf(
				"[member: %v] received multiple messages from sender [%d]",
				sm.index,
				message.senderIndex,
			)
			continue
		}

		// Sender's preferred DKG result hash doesn't match current member's
		// preferred DKG result hash.
		if message.resultHash != sm.preferredDKGResultHash {
			fmt.Printf(
				"[member: %v] signature from sender [%d] supports result different than preferred",
				sm.index,
				message.senderIndex,
			)
			continue
		}

		// Signature is invalid.
		err := operator.VerifySignature(
			message.publicKey,
			message.resultHash[:],
			message.signature,
		)
		if err != nil {
			fmt.Printf(
				"[member: %v] verification of signature from sender [%d] failed [%+v]",
				sm.index,
				message.senderIndex,
				message,
			)
			continue
		}

		receivedValidResultSignatures[message.senderIndex] = message.signature
	}

	// Register member's self signature.
	receivedValidResultSignatures[sm.index] = sm.selfDKGResultSignature

	return receivedValidResultSignatures, nil
}