package dkg2

import (
	"fmt"
	"math/big"

	relayChain "github.com/keep-network/keep-core/pkg/beacon/relay/chain"
	"github.com/keep-network/keep-core/pkg/beacon/relay/event"
	"github.com/keep-network/keep-core/pkg/chain"
)

// Publisher submits distributed key generation result to a blockchain.
type Publisher struct {
	// ID of distributed key generation execution.
	RequestID *big.Int
	// Initialized BlockCounter which allows for the reading, counting, and
	// waiting of blocks for the purposes of synchronization.
	blockCounter chain.BlockCounter
	// Sequential number of the current member in the publishing group.
	// The value is used to determine eligible publishing member. Indexing starts
	// with `1`. Relates to DKG Phase 13.
	publishingIndex int
	// Predefined step for each publishing window. The value is used to determine
	// eligible publishing member. Relates to DKG Phase 13.
	blockStep int

	conflictDuration int // T_conflict

	dishonestThreshold int // M
}

// executePublishing runs Distributed Key Generation result publication and voting,
// given unique identifier of DKG execution, a player index in the group, handler
// to interact with a chain and the Distributed Key Generation result in a format
// accepted by the chain.
func executePublishing(
	requestID *big.Int,
	publishingIndex int,
	chainRelay relayChain.Interface,
	blockCounter chain.BlockCounter,
	result *relayChain.DKGResult,
) error {
	if publishingIndex < 1 {
		return fmt.Errorf("publishing index must be >= 1")
	}

	publisher := &Publisher{
		RequestID:       requestID,
		blockCounter:    blockCounter,
		publishingIndex: publishingIndex,
		blockStep:       1,
	}

	_, err := publisher.publishResult(result, chainRelay)
	if err != nil {
		return fmt.Errorf("result publication failed [%v]", err)
	}

	// TODO Execute Phase 14 here

	return nil
}

// publishResult sends a result containing i.a. group public key to the blockchain.
// It checks if the result has already been published to the blockchain with
// request ID specific for current DKG execution. If not, it determines if the
// current member is eligable to result submission. If allowed, it submits the
// results to the blockchain.
//
// User allowance to publish is determined based on the user's publishing index
// and publishing block step.
//
// When member is waiting for their round the function keeps tracking results being
// published to the blockchain. If any result is published for the current
// request ID, the current member finishes the phase immediately, without
// publishing its own result.
//
// It returns chain block height of the moment when the result was published on
// chain by the publisher. In case of failure or result already published by
// another publisher it returns `-1`.
//
// See Phase 13 of the protocol specification.
func (pm *Publisher) publishResult(
	result *relayChain.DKGResult,
	chainRelay relayChain.Interface,
) (int, error) {
	onPublishedResultChan := make(chan *event.DKGResultPublication)

	subscription, err := chainRelay.OnDKGResultPublished(
		func(publishedResult *event.DKGResultPublication) {
			onPublishedResultChan <- publishedResult
		},
	)
	if err != nil {
		close(onPublishedResultChan)
		return -1, fmt.Errorf(
			"could not watch for DKG result publications [%v]",
			err,
		)
	}

	// Check if any result has already been published to the chain with current
	// request ID.
	alreadyPublished, err := chainRelay.IsDKGResultPublished(pm.RequestID)
	if err != nil {
		subscription.Unsubscribe()
		close(onPublishedResultChan)
		return -1, fmt.Errorf(
			"could not check if the result is already published [%v]",
			err,
		)
	}

	// Someone who was ahead of us in the queue published the result. Giving up.
	if alreadyPublished {
		subscription.Unsubscribe()
		close(onPublishedResultChan)
		return -1, nil
	}

	// Waits until the current member is eligible to submit a result to the
	// blockchain.
	eligibleToSubmitWaiter, err := pm.blockCounter.BlockWaiter(
		(pm.publishingIndex - 1) * pm.blockStep,
	)
	if err != nil {
		subscription.Unsubscribe()
		close(onPublishedResultChan)
		return -1, fmt.Errorf("block waiter failure [%v]", err)
	}

	for {
		select {
		case blockHeight := <-eligibleToSubmitWaiter:
			errorChannel := make(chan error)
			defer close(errorChannel)

			subscription.Unsubscribe()
			close(onPublishedResultChan)

			chainRelay.SubmitDKGResult(pm.RequestID, result).
				OnSuccess(func(dkgResultPublishedEvent *event.DKGResultPublication) {
					// TODO: This is a temporary solution until DKG Phase 14 is
					// ready. We assume that only one DKG result is published in
					// DKG Phase 13 and submit it as a final group public key.

					chainRelay.SubmitGroupPublicKey(
						pm.RequestID,
						dkgResultPublishedEvent.GroupPublicKey,
					).OnSuccess(func(groupRegisteredEvent *event.GroupRegistration) {
						fmt.Printf(
							"Group public key submitted for requestID=[%v]\n",
							pm.RequestID,
						)
						errorChannel <- nil
					}).OnFailure(func(err error) {
						errorChannel <- err
					})
				}).
				OnFailure(func(err error) {
					errorChannel <- err
				})
			return blockHeight, <-errorChannel
		case publishedResultEvent := <-onPublishedResultChan:
			if publishedResultEvent.RequestID.Cmp(pm.RequestID) == 0 {
				subscription.Unsubscribe()
				close(onPublishedResultChan)
				return -1, nil // leave without publishing the result
			}
		}
	}
}

// Phase14 - PHASE 14
func (pm *Publisher) Phase14(
	correctResult *relayChain.DKGResult,
	chainRelay relayChain.Interface,
) error {
	onVoteChan := make(chan *event.DKGResultVote)
	defer close(onVoteChan)
	onVoteSubscription, err := chainRelay.OnDKGResultVote(
		func(vote *event.DKGResultVote) {
			onVoteChan <- vote
		},
	)
	if err != nil {
		return fmt.Errorf(
			"could not watch for DKG result vote [%v]",
			err,
		)
	}
	defer onVoteSubscription.Unsubscribe()

	onSubmissionChan := make(chan *event.DKGResultPublication)
	defer close(onSubmissionChan)
	onSubmissionSubscription, err := chainRelay.OnDKGResultPublished(
		func(result *event.DKGResultPublication) {
			onSubmissionChan <- result
		},
	)
	if err != nil {
		return fmt.Errorf(
			"could not watch for DKG result vote [%v]",
			err,
		)
	}
	defer onSubmissionSubscription.Unsubscribe()

	errorChannel := make(chan error)
	defer close(errorChannel)

	// TODO: Do we need this?
	submissions := chainRelay.GetDKGSubmissions(pm.RequestID)
	if submissions == nil {
		return fmt.Errorf("nothing submitted")
	}

	if pm.leadHasEnoughVotes(submissions) {
		return nil
	}

	if !submissions.Contains(correctResult) {
		onSubmissionSubscription.Unsubscribe()

		chainRelay.SubmitDKGResult(pm.RequestID, correctResult).
			// TODO CHANGE TO OnComplete
			OnSuccess(func(dkgResultPublishedEvent *event.DKGResultPublication) {
				fmt.Printf(
					"result submitted for requestID=[%v]\n",
					dkgResultPublishedEvent.RequestID,
				)
				errorChannel <- nil
			}).
			OnFailure(func(err error) {
				errorChannel <- err
			})

		return <-errorChannel
	}

	// NOTE: We wait for T_conflict blocks but the protocol specification states
	// that we should wait for block `T_first + T_conflict`. Need clarification.
	phaseDurationWaiter, err := pm.blockCounter.BlockWaiter(pm.conflictDuration)
	if err != nil {
		return fmt.Errorf("block waiter failure [%v]", err)
	}

	// Returns already submitted
	votesAndSubmissions := func(chainRelay relayChain.Interface) (bool, error) {
		submissions := chainRelay.GetDKGSubmissions(pm.RequestID)

		if pm.leadHasEnoughVotes(submissions) {
			return false, nil
		}

		if submissions.IsOnlyLead(correctResult) {
			return false, nil
		}

		if submissions.Contains(correctResult) {
			chainRelay.DKGResultVote(pm.RequestID, correctResult.Hash()).
				OnSuccess(func(dkgResultVote *event.DKGResultVote) {
					fmt.Printf(
						"vote submitted for requestID=[%v]\n",
						dkgResultVote.RequestID,
					)
					errorChannel <- nil
				}).OnFailure(func(err error) {
				errorChannel <- err
			})
			return true, <-errorChannel
		}

		chainRelay.SubmitDKGResult(pm.RequestID, correctResult).
			OnSuccess(func(dkgResultPublishedEvent *event.DKGResultPublication) {
				fmt.Printf(
					"result submitted for requestID=[%v]\n",
					dkgResultPublishedEvent.RequestID,
				)
				errorChannel <- nil
			}).
			OnFailure(func(err error) {
				errorChannel <- err
			})
		return true, <-errorChannel
	}

	for {
		select {
		case <-phaseDurationWaiter:
			return nil
		case vote := <-onVoteChan:
			// TODO Check if channel is closed?
			if vote.RequestID.Cmp(pm.RequestID) == 0 {
				alreadySubmitted, err := votesAndSubmissions(chainRelay)
				if alreadySubmitted || err != nil {
					return err
				}
			}
		case submission := <-onSubmissionChan:
			// TODO Check if channel is closed?
			if submission.RequestID.Cmp(pm.RequestID) == 0 {
				alreadySubmitted, err := votesAndSubmissions(chainRelay)
				if alreadySubmitted || err != nil {
					return err
				}
			}
		}
	}
}

func (pm *Publisher) leadHasEnoughVotes(submissions *relayChain.DKGSubmissions) bool {
	if leads := submissions.Leads(); len(leads) > 0 {
		return submissions.Leads()[0].Votes > pm.dishonestThreshold
	}

	return false
}
