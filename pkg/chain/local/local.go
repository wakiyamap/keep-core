package local

import (
	"bytes"
	"fmt"
	"math/big"
	"os"
	"sync"
	"sync/atomic"

	relaychain "github.com/keep-network/keep-core/pkg/beacon/relay/chain"
	relayconfig "github.com/keep-network/keep-core/pkg/beacon/relay/config"
	"github.com/keep-network/keep-core/pkg/beacon/relay/event"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/gen/async"
	"github.com/pschlump/MiscLib"
	"github.com/pschlump/godebug"
)

type localChain struct {
	relayConfig relayconfig.Chain

	groupRegistrationsMutex sync.Mutex
	groupRegistrations      map[string][96]byte

	groupRelayEntriesMutex sync.Mutex
	groupRelayEntries      map[string]*big.Int

	submittedResultsMutex sync.Mutex
	// Map of submitted DKG Results. Key is a RequestID of the specific DKG
	// execution.
	submittedResults map[string][]*relaychain.DKGResult

	handlerMutex                 sync.Mutex
	relayEntryHandlers           []func(entry *event.Entry)
	relayRequestHandlers         []func(request *event.Request)
	groupRegisteredHandlers      []func(key *event.GroupRegistration)
	stakerRegistrationHandlers   []func(staker *event.StakerRegistration)
	dkgResultPublicationHandlers []func(dkgResultPublication *event.DKGResultPublication)

	requestID   int64
	latestValue *big.Int

	simulatedHeight int64
	stakeMonitor    chain.StakeMonitor
	blockCounter    chain.BlockCounter

	stakerList []string

	// Track the submitted votes -
	// Note: the map is on the "address" of an allocated big.Int, not on the value - so
	// this may be an error.
	submissionsMutex sync.Mutex
	submissions      map[string]relaychain.Submissions

	voteHandler []func(dkgResultVote *event.DKGResultVote)

	groupPublicKeyMapMutex sync.Mutex
	groupPublicKeyMap      map[string]*big.Int
}

// CurrentBlock rturns the current block number
func (c *localChain) CurrentBlock() (int, error) {
	return c.blockCounter.CurrentBlock()
}

// xyzzy - remove function/interface etc
// MapRequestIDToGroupPubKey Assoiciate requestID with a groupPubKey
func (c *localChain) MapRequestIDToGroupPubKey(requestID, groupPubKey *big.Int) error {
	c.groupPublicKeyMapMutex.Lock()
	defer c.groupPublicKeyMapMutex.Unlock()
	c.groupPublicKeyMap[bigIntToHex(requestID)] = groupPubKey
	return nil
}

// xyzzy - remove function/interface etc
// GetGroupPubKeyForRequestID given requestID return the groupPubKey
func (c *localChain) GetGroupPubKeyForRequestID(requestID *big.Int) (*big.Int, error) {
	c.groupPublicKeyMapMutex.Lock()
	defer c.groupPublicKeyMapMutex.Unlock()
	if groupPubKey, ok := c.groupPublicKeyMap[bigIntToHex(requestID)]; ok {
		return groupPubKey, nil
	}
	return nil, fmt.Errorf("invalid requestID [%s]", requestID)
}

func bigIntToHex(b *big.Int) string {
	return fmt.Sprintf("%s", b)
}

// GetDKGSubmissions returns the current set of submissions for the requestID.
func (c *localChain) GetDKGSubmissions(requestID *big.Int) *relaychain.Submissions {
	c.submissionsMutex.Lock()
	defer c.submissionsMutex.Unlock()
	x := c.submissions[bigIntToHex(requestID)]
	return &x
}

// Vote places a vote for dkgResultHash and causes OnDKGResultVote event to occurs.
func (c *localChain) Vote(requestID *big.Int, dkgResultHash []byte) {
	c.submissionsMutex.Lock()
	defer c.submissionsMutex.Unlock()
	x, ok := c.submissions[bigIntToHex(requestID)]
	if !ok {
		fmt.Fprintf(os.Stderr, "%sMissing requestID [%s] in c.submissions ->%s<- - vote will be ignored.%s\n", MiscLib.ColorRed, requestID, godebug.SVarI(c.submissions), MiscLib.ColorReset)
		return
	}
	for pos, sub := range x.Submissions {
		if bytes.Equal(sub.DKGResult.Hash(), dkgResultHash) {
			sub.Votes++
			x.Submissions[pos] = sub
			dkgResultVote := &event.DKGResultVote{
				RequestID: requestID,
			}
			c.handlerMutex.Lock()
			for _, handler := range c.voteHandler {
				go func(handler func(*event.DKGResultVote), dkgResultVote *event.DKGResultVote) {
					handler(dkgResultVote)
				}(handler, dkgResultVote)
			}
			c.handlerMutex.Unlock()
			return
		}
	}
}

// OnDKGResultVote sets up to call the passed handler function when a vote occurs.
func (c *localChain) OnDKGResultVote(handler func(dkgResultVote *event.DKGResultVote)) {
	c.handlerMutex.Lock()
	c.voteHandler = append(c.voteHandler, handler)
	c.handlerMutex.Unlock()
}

func (c *localChain) BlockCounter() (chain.BlockCounter, error) {
	return c.blockCounter, nil
}

func (c *localChain) StakeMonitor() (chain.StakeMonitor, error) {
	return c.stakeMonitor, nil
}

func (c *localChain) GetConfig() (relayconfig.Chain, error) {
	return c.relayConfig, nil
}

func (c *localChain) SubmitGroupPublicKey(
	requestID *big.Int,
	key [96]byte,
) *async.GroupRegistrationPromise {
	groupID := requestID.String()

	groupRegistrationPromise := &async.GroupRegistrationPromise{}
	registration := &event.GroupRegistration{
		GroupPublicKey:        key[:],
		RequestID:             requestID,
		ActivationBlockHeight: big.NewInt(c.simulatedHeight),
	}

	c.groupRegistrationsMutex.Lock()
	defer c.groupRegistrationsMutex.Unlock()
	if existing, exists := c.groupRegistrations[groupID]; exists {
		if existing != key {
			err := fmt.Errorf(
				"mismatched public key for [%s], submission failed; \n"+
					"[%v] vs [%v]",
				groupID,
				existing,
				key,
			)
			fmt.Fprintf(os.Stderr, err.Error())

			groupRegistrationPromise.Fail(err)
		} else {
			groupRegistrationPromise.Fulfill(registration)
		}

		return groupRegistrationPromise
	}
	c.groupRegistrations[groupID] = key

	groupRegistrationPromise.Fulfill(registration)

	c.handlerMutex.Lock()
	for _, handler := range c.groupRegisteredHandlers {
		go func(handler func(registration *event.GroupRegistration), registration *event.GroupRegistration) {
			handler(registration)
		}(handler, registration)
	}
	c.handlerMutex.Unlock()

	atomic.AddInt64(&c.simulatedHeight, 1)

	return groupRegistrationPromise
}

func (c *localChain) SubmitRelayEntry(entry *event.Entry) *async.RelayEntryPromise {
	relayEntryPromise := &async.RelayEntryPromise{}

	c.groupRelayEntriesMutex.Lock()
	defer c.groupRelayEntriesMutex.Unlock()

	existing, exists := c.groupRelayEntries[entry.GroupID.String()+entry.RequestID.String()]
	if exists {
		if existing != entry.Value {
			err := fmt.Errorf(
				"mismatched signature for [%v], submission failed; \n"+
					"[%v] vs [%v]\n",
				entry.GroupID,
				existing,
				entry.Value,
			)

			relayEntryPromise.Fail(err)
		} else {
			relayEntryPromise.Fulfill(entry)
		}

		return relayEntryPromise
	}
	c.groupRelayEntries[entry.GroupID.String()+entry.RequestID.String()] = entry.Value

	c.handlerMutex.Lock()
	for _, handler := range c.relayEntryHandlers {
		go func(handler func(entry *event.Entry), entry *event.Entry) {
			handler(entry)
		}(handler, entry)
	}
	c.handlerMutex.Unlock()

	c.latestValue = entry.Value
	relayEntryPromise.Fulfill(entry)

	return relayEntryPromise
}

func (c *localChain) OnRelayEntryGenerated(handler func(entry *event.Entry)) {
	c.handlerMutex.Lock()
	c.relayEntryHandlers = append(
		c.relayEntryHandlers,
		handler,
	)
	c.handlerMutex.Unlock()
}

func (c *localChain) OnRelayEntryRequested(handler func(request *event.Request)) {
	c.handlerMutex.Lock()
	c.relayRequestHandlers = append(
		c.relayRequestHandlers,
		handler,
	)
	c.handlerMutex.Unlock()
}

func (c *localChain) OnGroupRegistered(handler func(key *event.GroupRegistration)) {
	c.handlerMutex.Lock()
	c.groupRegisteredHandlers = append(
		c.groupRegisteredHandlers,
		handler,
	)
	c.handlerMutex.Unlock()
}

func (c *localChain) OnStakerAdded(handler func(staker *event.StakerRegistration)) {
	c.handlerMutex.Lock()
	c.stakerRegistrationHandlers = append(
		c.stakerRegistrationHandlers,
		handler,
	)
	c.handlerMutex.Unlock()
}

func (c *localChain) ThresholdRelay() relaychain.Interface {
	return relaychain.Interface(c)
}

// Connect initializes a local stub implementation of the chain interfaces
// for testing.
func Connect(groupSize int, threshold int) chain.Handle {
	bc, _ := blockCounter()

	fmt.Printf("\n\n---- Connect ---, called from %s\n\n", godebug.LF(2))
	return &localChain{
		relayConfig: relayconfig.Chain{
			GroupSize: groupSize,
			Threshold: threshold,
		},
		groupRegistrationsMutex: sync.Mutex{},
		groupRelayEntries:       make(map[string]*big.Int),
		groupRegistrations:      make(map[string][96]byte),
		submittedResults:        make(map[string][]*relaychain.DKGResult),
		blockCounter:            bc,
		stakeMonitor:            NewStakeMonitor(),
		submissions:             make(map[string]relaychain.Submissions),
		groupPublicKeyMapMutex:  sync.Mutex{},
		groupPublicKeyMap:       make(map[string]*big.Int),
	}
}

// AddStaker is a temporary function for Milestone 1 that
// adds a staker to the group contract.
func (c *localChain) AddStaker(
	groupMemberID string,
) *async.StakerRegistrationPromise {
	onStakerAddedPromise := &async.StakerRegistrationPromise{}
	index := len(c.stakerList)
	c.stakerList = append(c.stakerList, groupMemberID)

	c.handlerMutex.Lock()
	for _, handler := range c.stakerRegistrationHandlers {
		go func(handler func(staker *event.StakerRegistration), groupMemberID string, index int) {
			handler(&event.StakerRegistration{
				GroupMemberID: groupMemberID,
				Index:         index,
			})
		}(handler, groupMemberID, index)
	}
	c.handlerMutex.Unlock()

	err := onStakerAddedPromise.Fulfill(&event.StakerRegistration{
		Index:         index,
		GroupMemberID: string(groupMemberID),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Promise Fulfill failed [%v].\n", err)
	}

	return onStakerAddedPromise
}

// GetStakerList is a temporary function for Milestone 1 that
// gets back the list of stakers.
func (c *localChain) GetStakerList() ([]string, error) {
	return c.stakerList, nil
}

// RequestRelayEntry simulates calling to start the random generation process.
func (c *localChain) RequestRelayEntry(
	blockReward, seed *big.Int,
) *async.RelayRequestPromise {
	promise := &async.RelayRequestPromise{}

	request := &event.Request{
		PreviousValue: c.latestValue,
		RequestID:     big.NewInt(c.requestID),
		Payment:       big.NewInt(1),
		BlockReward:   blockReward,
		Seed:          seed,
	}
	atomic.AddInt64(&c.simulatedHeight, 1)
	atomic.AddInt64(&c.requestID, 1)

	c.handlerMutex.Lock()
	for _, handler := range c.relayRequestHandlers {
		go func(handler func(*event.Request), request *event.Request) {
			handler(request)
		}(handler, request)
	}
	c.handlerMutex.Unlock()

	promise.Fulfill(request)

	return promise
}

// IsDKGResultPublished simulates check if the result was already submitted to a
// chain.
func (c *localChain) IsDKGResultPublished(
	requestID *big.Int, result *relaychain.DKGResult,
) bool {
	requestIDstr := bigIntToHex(requestID)
	fmt.Printf("IsDKGResultPublished: requestID = %s, result = %s, c.submittedResults = %s\n",
		requestIDstr, godebug.SVarI(result), godebug.SVarI(c.submittedResults))
	if publishedResults, ok := c.submittedResults[requestIDstr]; ok {
		for _, publishedResult := range publishedResults {
			if publishedResult.Equals(result) {
				fmt.Printf("\nIsDKGResultPublished: return true\n")
				return true
			}
		}
	}
	fmt.Printf("\nIsDKGResultPublished: return false\n")
	return false
}

// SubmitDKGResult submits the result to a chain.
func (c *localChain) SubmitDKGResult(
	requestID *big.Int, resultToPublish *relaychain.DKGResult,
) *async.DKGResultPublicationPromise {
	requestIDstr := bigIntToHex(requestID)
	c.submittedResultsMutex.Lock()
	defer c.submittedResultsMutex.Unlock()

	if db1 {
		fmt.Printf("%sAt: %s\n\tcalled from %s%s\n", MiscLib.ColorCyan, godebug.LF(), godebug.LF(2), MiscLib.ColorReset)
	}
	dkgResultPublicationPromise := &async.DKGResultPublicationPromise{}

	if c.IsDKGResultPublished(requestID, resultToPublish) {
		if db1 {
			fmt.Printf("%sAt: %s%s\n", MiscLib.ColorCyan, godebug.LF(), MiscLib.ColorReset)
		}
		dkgResultPublicationPromise.Fail(fmt.Errorf("result already submitted"))
		return dkgResultPublicationPromise
	}

	c.submittedResults[requestIDstr] = append(c.submittedResults[requestIDstr], resultToPublish)

	if db1 {
		fmt.Printf("%sAt: %s%s\n", MiscLib.ColorCyan, godebug.LF(), MiscLib.ColorReset)
	}
	c.submissionsMutex.Lock()
	if c.submissions == nil {
		c.submissions = make(map[string]relaychain.Submissions)
	}
	if _, ok := c.submissions[requestIDstr]; !ok {
		if db1 {
			fmt.Printf("%sAt: %s%s\n", MiscLib.ColorCyan, godebug.LF(), MiscLib.ColorReset)
			fmt.Printf("%s\tMUST SEE THIS! At: %s%s\n", MiscLib.ColorGreen, godebug.LF(), MiscLib.ColorReset)
		}
		/*
			xyzzy remove comment
						groupPublicKey, err := c.GetGroupPubKeyForRequestID(requestID)
						if err != nil || groupPublicKey == nil {
							fmt.Printf("%s!!! Error - could not get GroupPubKey for requestID=[%s] At: %s%s\n",
								MiscLib.ColorRed, requestID, godebug.LF(), MiscLib.ColorReset)
						}
		*/
		if db1 {
			fmt.Printf("%sAt: %s%s\n", MiscLib.ColorCyan, godebug.LF(), MiscLib.ColorReset)
		}
		c.submissions[requestIDstr] = relaychain.Submissions{
			Submissions: []*relaychain.Submission{
				{
					DKGResult: resultToPublish,
					Votes:     1,
				},
			},
		}
	}
	c.submissionsMutex.Unlock()

	if db1 {
		fmt.Printf("%s*** FINAL *** At: %s, Submissions.submissions set ->%s<-\n c.submittedResults ->%s<- %s\n",
			MiscLib.ColorCyan, godebug.LF(), godebug.SVarI(c.submissions), godebug.SVarI(c.submittedResults), MiscLib.ColorReset)
	}

	// ----------------------------------------------------------------------------------
	// Process event below this point.
	// ----------------------------------------------------------------------------------

	dkgResultPublicationEvent := &event.DKGResultPublication{RequestID: requestID}

	if db1 {
		fmt.Printf("%sAt: %s%s\n", MiscLib.ColorCyan, godebug.LF(), MiscLib.ColorReset)
	}
	c.handlerMutex.Lock()
	for _, handler := range c.dkgResultPublicationHandlers {
		if db1 {
			fmt.Printf("%sAt: %s%s\n", MiscLib.ColorCyan, godebug.LF(), MiscLib.ColorReset)
		}
		go func(handler func(*event.DKGResultPublication), dkgResultPublication *event.DKGResultPublication) {
			handler(dkgResultPublicationEvent)
		}(handler, dkgResultPublicationEvent)
	}
	c.handlerMutex.Unlock()

	if db1 {
		fmt.Printf("%sAt: %s%s\n", MiscLib.ColorCyan, godebug.LF(), MiscLib.ColorReset)
	}
	err := dkgResultPublicationPromise.Fulfill(dkgResultPublicationEvent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "promise fulfill failed [%v].\n", err)
	}

	return dkgResultPublicationPromise
}

func (c *localChain) OnDKGResultPublished(
	handler func(dkgResultPublication *event.DKGResultPublication),
) {
	c.handlerMutex.Lock()
	defer c.handlerMutex.Unlock()

	c.dkgResultPublicationHandlers = append(
		c.dkgResultPublicationHandlers,
		handler,
	)
}

const db1 = false
