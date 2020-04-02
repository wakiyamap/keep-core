// Package groupselection implements the random beacon group selection protocol
// - an interactive, ticket-based method of selecting a candidate group from
// the set of all stakers given a pseudorandom seed value.
package groupselection

import (
	"fmt"
	"math/big"
	"sort"

	"github.com/ipfs/go-log"

	relaychain "github.com/keep-network/keep-core/pkg/beacon/relay/chain"
	"github.com/keep-network/keep-core/pkg/beacon/relay/config"
	"github.com/keep-network/keep-core/pkg/chain"
)

var logger = log.Logger("keep-groupselection")

// Duration of one ticket submission round in blocks. Should correspond
// to the value set in group selection contract.
const ticketSubmissionRoundDuration = 6

// Result represents the result of group selection protocol. It contains the
// list of all stakers selected to the candidate group as well as the number of
// block at which the group selection protocol completed.
type Result struct {
	SelectedStakers        []relaychain.StakerAddress
	GroupSelectionEndBlock uint64
}

// CandidateToNewGroup attempts to generate and submit tickets for the staker to
// join a new group.
//
// The function never submits more tickets than the group size.
func CandidateToNewGroup(
	relayChain relaychain.Interface,
	blockCounter chain.BlockCounter,
	chainConfig *config.Chain,
	staker chain.Staker,
	newEntry *big.Int,
	startBlockHeight uint64,
	onGroupSelected func(*Result),
) error {
	availableStake, err := staker.Stake()
	if err != nil {
		return err
	}

	tickets, err := generateTickets(
		newEntry.Bytes(),
		staker.Address(),
		availableStake,
		chainConfig.MinimumStake,
	)
	if err != nil {
		return err
	}

	logger.Infof("generated [%v] tickets", len(tickets))

	return startTicketSubmission(
		tickets,
		relayChain,
		blockCounter,
		chainConfig,
		startBlockHeight,
		onGroupSelected,
		ticketSubmissionRoundDuration,
	)
}

func startTicketSubmission(
	tickets []*ticket,
	relayChain relaychain.GroupSelectionInterface,
	blockCounter chain.BlockCounter,
	chainConfig *config.Chain,
	startBlockHeight uint64,
	onGroupSelected func(*Result),
	ticketSubmissionRoundDuration uint64,
) error {
	ticketSubmissionTimeout, err := relayChain.TicketSubmissionTimeout()
	if err != nil {
		return err
	}

	ticketSubmissionTimeoutChannel, err := blockCounter.BlockHeightWaiter(
		startBlockHeight + ticketSubmissionTimeout.Uint64(),
	)
	if err != nil {
		return err
	}

	quitTicketSubmission := make(chan struct{})

	ticketSubmissionRounds := (ticketSubmissionTimeout.Uint64() /
		ticketSubmissionRoundDuration) - 2

	for roundIndex := uint64(0); roundIndex <= ticketSubmissionRounds; roundIndex++ {
		roundStartDelay := roundIndex * ticketSubmissionRoundDuration
		roundStartBlock := startBlockHeight + roundStartDelay
		roundLeadingZeros := ticketSubmissionRounds - roundIndex

		logger.Infof(
			"ticket submission round [%v] will start at "+
				"block [%v] and cover tickets with [%v] leading zeros",
			roundIndex,
			roundStartBlock,
			roundLeadingZeros,
		)

		err := blockCounter.WaitForBlockHeight(roundStartBlock)
		if err != nil {
			return err
		}

		candidateTickets, err := roundCandidateTickets(
			relayChain,
			tickets,
			roundIndex,
			roundLeadingZeros,
			chainConfig.GroupSize,
		)
		if err != nil {
			return err
		}

		logger.Infof(
			"ticket submission round [%v] submitting "+
				"[%v] tickets",
			roundIndex,
			len(candidateTickets),
		)

		go submitTickets(
			candidateTickets,
			relayChain,
			quitTicketSubmission,
		)
	}

	ticketSubmissionEndBlockHeight := <-ticketSubmissionTimeoutChannel

	logger.Infof(
		"ticket submission ended at block [%v]",
		ticketSubmissionEndBlockHeight,
	)

	close(quitTicketSubmission)

	selectedStakers, err := relayChain.GetSelectedParticipants()
	if err != nil {
		return fmt.Errorf(
			"could not fetch selected participants after submission timeout [%v]",
			err,
		)
	}

	go onGroupSelected(&Result{
		SelectedStakers:        selectedStakers,
		GroupSelectionEndBlock: ticketSubmissionEndBlockHeight,
	})

	return nil
}

// roundCandidateTickets returns tickets which should be submitted in
// given ticket submission round.
func roundCandidateTickets(
	relayChain relaychain.GroupSelectionInterface,
	tickets []*ticket,
	roundIndex uint64,
	roundLeadingZeros uint64,
	groupSize int,
) ([]*ticket, error) {

	// Get unsorted submitted tickets from the chain.
	// This slice will be also filled by candidate tickets values
	// in order to determine an optimal number of candidate tickets.
	submittedTickets, err := relayChain.GetSubmittedTickets()
	if err != nil {
		return nil, fmt.Errorf(
			"could not get submitted tickets: [%v]",
			err,
		)
	}

	candidateTickets := make([]*ticket, 0)

	for _, candidateTicket := range tickets {
		candidateTicketLeadingZeros := uint64(
			candidateTicket.leadingZeros(),
		)

		// Check if given candidate ticket should be proceeded in current round.
		if roundIndex == 0 {
			if candidateTicketLeadingZeros < roundLeadingZeros {
				continue
			}
		} else {
			if candidateTicketLeadingZeros != roundLeadingZeros {
				continue
			}
		}

		// Sort submitted tickets slice in ascending order.
		sort.SliceStable(
			submittedTickets,
			func(i, j int) bool {
				return submittedTickets[i] < submittedTickets[j]
			},
		)

		// If previous iteration encountered the maximum length
		// of submitted tickets slice and was able to add a new
		// candidate value, submitted tickets slice should be
		// trimmed to the group size.
		if len(submittedTickets) > groupSize {
			submittedTickets = submittedTickets[:groupSize]
		}

		shouldBeSubmitted := false
		candidateTicketValue := candidateTicket.intValue().Uint64()

		if len(submittedTickets) < groupSize {
			// If submitted tickets count is less than the group
			// size the candidate ticket can be added unconditionally.
			submittedTickets = append(
				submittedTickets,
				candidateTicketValue,
			)
			shouldBeSubmitted = true
		} else {
			// If submitted tickets count is equal to the group
			// size the candidate ticket can be added only if
			// it is smaller than the highest submitted ticket.
			// Note that, maximum length of submitted tickets slice
			// will be exceeded and will be trimmed in next
			// iteration.
			highestSubmittedTicket := submittedTickets[len(submittedTickets)-1]
			if candidateTicketValue < highestSubmittedTicket {
				submittedTickets = append(
					submittedTickets,
					candidateTicketValue,
				)
				shouldBeSubmitted = true
			}
		}

		// If current candidate ticket should not be submitted,
		// there is no sense to continue with next candidate tickets
		// because they will have higher value than the current one.
		if !shouldBeSubmitted {
			break
		}

		candidateTickets = append(
			candidateTickets,
			candidateTicket,
		)
	}

	return candidateTickets, nil
}
