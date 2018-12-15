package publish

import (
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	relayChain "github.com/keep-network/keep-core/pkg/beacon/relay/chain"
	"github.com/keep-network/keep-core/pkg/beacon/relay/gjkr"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/chain/local"
	"github.com/pschlump/MiscLib"
	"github.com/pschlump/godebug"
)

/*
type DKGResult struct {
	// Result type of the protocol execution. True if success, false if failure.
	Success bool
	// Group public key generated by protocol execution.
	GroupPublicKey *big.Int
	// Disqualified members. Length of the slice and order of members are the same
	// as in the members group. Disqualified members are marked as true. It is
	// kept in this form as an optimization for an on-chain storage.
	Disqualified []bool
	// Inactive members. Length of the slice and order of members are the same
	// as in the members group. Disqualified members are marked as true. It is
	// kept in this form as an optimization for an on-chain storage.
	Inactive []bool
}
			dkgResultVote := &event.DKGResultVote{
				RequestID: requestID,
			}
type DKGResultPublication struct {
	RequestID *big.Int
}
*/

func TestPhase14_pt1(t *testing.T) {
	threshold := 2
	groupSize := 5
	blockStep := 2 // T_step

	chainHandle, _ /*initialBlock*/, err := initChainHandle2(threshold, groupSize)
	if err != nil {
		t.Fatal(err)
	}

	type runCode struct {
		op              string
		requestID       *big.Int
		groupPubKey     *big.Int
		dkgResult       *relayChain.DKGResult
		intVal          int
		intVal2         int
		resultToPublish *relayChain.DKGResult
	}

	var tests = map[string]struct {
		runIt           bool
		correctResult   *relayChain.DKGResult
		publishingIndex int
		steps           []runCode
	}{
		"vote test with no data, nothing submitted": {
			runIt: false,
			correctResult: &relayChain.DKGResult{
				GroupPublicKey: big.NewInt(4000),
			},
			publishingIndex: 0,
			steps: []runCode{
				{
					op: "call-phase14",
				},
			},
		},
		"vote test with no data, nothing submitted - using go-routine": {
			runIt: false,
			correctResult: &relayChain.DKGResult{
				GroupPublicKey: big.NewInt(4001),
			},
			publishingIndex: 0,
			steps: []runCode{
				{
					op: "go-phase14",
				},
			},
		},
		"setup a map from 2 ReqeustID-s to a singel GroupPublicKey": {
			runIt: false,
			correctResult: &relayChain.DKGResult{
				GroupPublicKey: big.NewInt(4001),
			},
			publishingIndex: 0,
			steps: []runCode{
				{
					op:          "setup-requestID-to-GroupPubKey",
					requestID:   big.NewInt(101),
					groupPubKey: big.NewInt(4001),
				},
				{
					op:          "setup-requestID-to-GroupPubKey",
					requestID:   big.NewInt(102),
					groupPubKey: big.NewInt(4001),
				},
				{
					op: "go-phase14",
				},
			},
		},
		"send a Vote - 1 vote after start": {
			runIt: true,
			correctResult: &relayChain.DKGResult{
				GroupPublicKey: big.NewInt(4001),
			},
			publishingIndex: 0,
			steps: []runCode{
				//				{
				//					op:          "setup-requestID-to-GroupPubKey",
				//					requestID:   big.NewInt(101),
				//					groupPubKey: big.NewInt(4001),
				//				},
				{
					op:          "setup-requestID-to-GroupPubKey",
					requestID:   big.NewInt(102),
					groupPubKey: big.NewInt(4001),
				},
				// {op: "sleep-1-sec"},
				{
					op:        "submit-result",
					requestID: big.NewInt(102),
					resultToPublish: &relayChain.DKGResult{
						Success:        true,
						GroupPublicKey: big.NewInt(4001),
					},
				},
				{op: "call-phase14"}, // Places result onto channel
				{op: "sleep", intVal: 500},
				{op: "go-phase14"}, // Process result
				{
					op:        "send-vote",
					requestID: big.NewInt(102),
					dkgResult: &relayChain.DKGResult{
						Success:        true,
						GroupPublicKey: big.NewInt(4001),
					},
				},
				{op: "dump-submissions", requestID: big.NewInt(102)},
				{
					op:        "validate-votes",
					requestID: big.NewInt(102), // request to check
					intVal:    2,               // # of votes to expect
					intVal2:   0,               // positon in submission set
				},
			},
		},
		// Send a Vote for a result
		// Create a result and call with 1 result alreay in place
	}

	thresholdRelayChain := chainHandle.ThresholdRelay()
	var wg sync.WaitGroup

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			if !test.runIt {
				return
			}
			publisher := &Publisher{
				ID:               gjkr.MemberID(test.publishingIndex + 1),
				RequestID:        big.NewInt(102),
				publishingIndex:  test.publishingIndex,
				chainHandle:      chainHandle,
				blockStep:        blockStep,
				conflictDuration: 8, // T_conflict
				votingThreshold:  3, // T_max
			}

			// Reinitialize chain to reset block counter
			// publisher.chainHandle, initialBlock, err = initChainHandle2(threshold, groupSize)
			// if err != nil {
			// 	t.Fatalf("chain initialization failed [%v]", err)
			// }

			// func (pm *Publisher) Phase14(correctResult *relayChain.DKGResult) error {
			for pc, ex := range test.steps {
				fmt.Printf("%s------ Running %s ------%s\n", MiscLib.ColorGreen, ex.op, MiscLib.ColorReset)
				switch ex.op {
				case "sleep-1-sec":
					fmt.Printf("*** Sleep for 1 sec ***\n")
					time.Sleep(1 * time.Second)
				case "sleep":
					fmt.Printf("*** Sleep for %d millisecond ***\n", ex.intVal)
					time.Sleep(time.Duration(ex.intVal) * time.Millisecond)
				case "call-phase14": // blocking call to publisher.Phase14!
					publisher.Phase14(test.correctResult)
				case "submit-result":
					promise := thresholdRelayChain.SubmitDKGResult(ex.requestID, ex.resultToPublish)
					_ = promise // local test will immediately fulfil so can be ignored.
				case "setup-requestID-to-GroupPubKey":
					// func (c *localChain) MapRequestIDToGroupPubKey(requestID, groupPubKey *big.Int) error {
					err := thresholdRelayChain.MapRequestIDToGroupPubKey(ex.requestID, ex.groupPubKey)
					if err != nil {
						fmt.Printf("Error: %s\n", err)
					}
				case "dump-submissions":
					submissions := thresholdRelayChain.GetDKGSubmissions(ex.requestID)
					fmt.Printf("submissions ->%s<-\n", godebug.SVarI(submissions))
				case "validate-votes": // intVal: 2},
					submissions := thresholdRelayChain.GetDKGSubmissions(ex.requestID)
					votes := submissions.Submissions[ex.intVal2].Votes
					if votes != ex.intVal {
						fmt.Printf("%s**** Error on votes%s\n", MiscLib.ColorRed, MiscLib.ColorReset)
						// xyzzy - add t.Errorf!
					}
				case "send-vote":
					dkgResultHash := ex.dkgResult.Hash()
					thresholdRelayChain.Vote(ex.requestID, dkgResultHash)
				case "go-phase14":
					wg.Add(1)
					go func() {
						defer wg.Done()
						publisher.Phase14(test.correctResult)
					}()
				default:
					fmt.Printf("In test [%s] invalid op [%s] at %d\n", testName, ex.op, pc)
				}
			}
		})
	}

	wg.Wait()
}

/*
	chainRelay := publisher.chainHandle.ThresholdRelay()
	_ = chainRelay

	blockCounter, err := publisher.chainHandle.BlockCounter()
	if err != nil {
		t.Fatalf("unexpected error [%v]", err)
	}
	_ = blockCounter
*/

func initChainHandle2(threshold, groupSize int) (chainHandle chain.Handle, initialBlock int, err error) {
	chainHandle = local.Connect(groupSize, threshold)
	blockCounter, err := chainHandle.BlockCounter() // PJS - save blockCounter?
	if err != nil {
		return nil, -1, err
	}
	err = blockCounter.WaitForBlocks(1)
	if err != nil {
		return nil, -1, err
	}

	initialBlock, err = blockCounter.CurrentBlock() // PJS - need CurrentBlock to make this work
	if err != nil {
		return nil, -1, err
	}
	return
}
