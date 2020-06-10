package libp2p

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	protoio "github.com/gogo/protobuf/io"
	keepNet "github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/net/gen/pb"
	"github.com/keep-network/keep-core/pkg/net/key"
	"github.com/keep-network/keep-core/pkg/net/security/handshake"
	libp2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
	peer "github.com/libp2p/go-libp2p-core/peer"
)

func TestPinnedAndMessageKeyMismatch(t *testing.T) {
	initiator := createTestConnectionConfig(t)
	responder := createTestConnectionConfig(t)

	firewall := newMockFirewall()
	firewall.updatePeer(initiator.pubKey, true)
	firewall.updatePeer(responder.pubKey, true)

	initiatorConn, responderConn := newConnPair()

	go func(
		initiatorConn net.Conn,
		initiatorPeerID peer.ID,
		initiatorStaticKey libp2pcrypto.PrivKey,
		responderPeerID peer.ID,
		responderStaticKey libp2pcrypto.PrivKey,
	) {
		ac := &authenticatedConnection{
			Conn:                initiatorConn,
			localPeerID:         initiatorPeerID,
			localPeerPrivateKey: initiatorStaticKey,
			remotePeerID:        responderPeerID,
			remotePeerPublicKey: responderStaticKey.GetPublic(),
		}

		maliciousInitiatorHijacksHonestRun(t, ac)
	}(initiatorConn, initiator.peerID, initiator.privKey, responder.peerID, responder.privKey)

	_, err := newAuthenticatedInboundConnection(
		responderConn,
		responder.peerID,
		responder.privKey,
		firewall,
		ProtocolBeacon,
	)
	if err == nil {
		t.Fatal("should not have successfully completed handshake")
	}
}

// maliciousInitiatorHijacksHonestRun simulates an honest Acts 1 and 2 as an
// initiator, and then drops in a malicious peer for Act 3. Properly implemented
// peer-pinning should ensure that a malicious peer can't hijack a connection
// after the first act and sign subsequent messages.
func maliciousInitiatorHijacksHonestRun(t *testing.T, ac *authenticatedConnection) {
	initiatorConnectionReader := protoio.NewDelimitedReader(ac.Conn, maxFrameSize)
	initiatorConnectionWriter := protoio.NewDelimitedWriter(ac.Conn)

	initiatorAct1, err := handshake.InitiateHandshake(ProtocolBeacon)
	if err != nil {
		t.Fatal(err)
	}

	act1WireMessage, err := initiatorAct1.Message().Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if err := ac.initiatorSendAct1(act1WireMessage, initiatorConnectionWriter); err != nil {
		t.Fatal(err)
	}

	initiatorAct2 := initiatorAct1.Next()

	act2Message, err := ac.initiatorReceiveAct2(initiatorConnectionReader)
	if err != nil {
		t.Fatal(err)
	}

	initiatorAct3, err := initiatorAct2.Next(act2Message)
	if err != nil {
		t.Fatal(err)
	}

	act3WireMessage, err := initiatorAct3.Message().Marshal()
	if err != nil {
		t.Fatal(err)
	}

	maliciousInitiator := createTestConnectionConfig(t)
	signedAct3Message, err := maliciousInitiator.privKey.Sign(act3WireMessage)
	if err != nil {
		t.Fatal(err)
	}

	act3Envelope := &pb.HandshakeEnvelope{
		Message:   act3WireMessage,
		PeerID:    []byte(maliciousInitiator.peerID),
		Signature: signedAct3Message,
	}

	if err := initiatorConnectionWriter.WriteMsg(act3Envelope); err != nil {
		t.Fatal(err)
	}
}

func TestHandshake(t *testing.T) {
	_, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	initiator := createTestConnectionConfig(t)
	responder := createTestConnectionConfig(t)

	firewall := newMockFirewall()
	firewall.updatePeer(initiator.pubKey, true)
	firewall.updatePeer(responder.pubKey, true)

	authnInboundConn, authnOutboundConn, inboundError, outboundError :=
		connectInitiatorAndResponder(initiator, responder, firewall, t)
	if inboundError != nil {
		t.Fatal(inboundError)
	}
	if outboundError != nil {
		t.Fatal(outboundError)
	}

	// send a test message over the established connection
	msg := []byte("brown fox blue tail")
	go func(authnOutboundConn *authenticatedConnection, msg []byte) {
		if _, err := authnOutboundConn.Write(msg); err != nil {
			t.Error(err)
		}
	}(authnOutboundConn, msg)

	msgContainer := make([]byte, len(msg))
	if _, err := io.ReadFull(authnInboundConn.Conn, msgContainer); err != nil {
		t.Fatal(err)
	}

	if string(msgContainer) != string(msg) {
		t.Fatalf("message mismatch got %v, want %v", string(msgContainer), string(msg))
	}
}

func TestHandshakeInitiatorBlockedByFirewallRules(t *testing.T) {
	_, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	initiator := createTestConnectionConfig(t)
	responder := createTestConnectionConfig(t)

	firewall := newMockFirewall()
	// only responder meets firewall rules
	firewall.updatePeer(responder.pubKey, true)

	_, _, inboundError, outboundError :=
		connectInitiatorAndResponder(initiator, responder, firewall, t)

	if inboundError != nil {
		t.Fatal(inboundError)
	}

	expectedOutboundError := fmt.Errorf("connection handshake failed: [remote peer does not meet firewall criteria]")
	if !reflect.DeepEqual(expectedOutboundError, outboundError) {
		t.Fatalf(
			"unexpected outbound connection error\nexpected: %v\nactual: %v",
			expectedOutboundError,
			outboundError,
		)
	}
}

func TestHandshakeResponderBlockedByFirewallRules(t *testing.T) {
	_, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	initiator := createTestConnectionConfig(t)
	responder := createTestConnectionConfig(t)

	firewall := newMockFirewall()
	// only initiator meets firewall rules
	firewall.updatePeer(initiator.pubKey, true)

	_, _, inboundError, outboundError :=
		connectInitiatorAndResponder(initiator, responder, firewall, t)

	expectedInboundError := fmt.Errorf("connection handshake failed: [remote peer does not meet firewall criteria]")
	if !reflect.DeepEqual(expectedInboundError, inboundError) {
		t.Fatalf(
			"unexpected outbound connection error\nexpected: %v\nactual: %v",
			expectedInboundError,
			inboundError,
		)
	}

	if outboundError != nil {
		t.Fatal(outboundError)
	}
}

func connectInitiatorAndResponder(
	initiator *testConnectionConfig,
	responder *testConnectionConfig,
	firewall keepNet.Firewall,
	t *testing.T,
) (
	authnInboundConn *authenticatedConnection,
	authnOutboundConn *authenticatedConnection,
	outboundError error,
	inboundError error,
) {

	initiatorConn, responderConn := newConnPair()

	done := make(chan struct{})

	go func(
		initiatorConn net.Conn,
		initiatorPeerID peer.ID,
		initiatorPrivKey libp2pcrypto.PrivKey,
		responderPeerID peer.ID,
	) {
		authnOutboundConn, outboundError = newAuthenticatedOutboundConnection(
			initiatorConn,
			initiatorPeerID,
			initiatorPrivKey,
			responderPeerID,
			firewall,
			ProtocolBeacon,
		)
		done <- struct{}{}
	}(initiatorConn, initiator.peerID, initiator.privKey, responder.peerID)

	authnInboundConn, inboundError = newAuthenticatedInboundConnection(
		responderConn,
		responder.peerID,
		responder.privKey,
		firewall,
		ProtocolBeacon,
	)

	<-done // handshake is done

	return
}

type testConnectionConfig struct {
	privKey *key.NetworkPrivate
	pubKey  *key.NetworkPublic
	peerID  peer.ID
}

func createTestConnectionConfig(t *testing.T) *testConnectionConfig {
	privKey, pubKey, err := key.GenerateStaticNetworkKey()
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := peer.IDFromPrivateKey(privKey)
	if err != nil {
		t.Fatal(err)
	}

	return &testConnectionConfig{privKey, pubKey, peerID}
}

// Connect an initiator and responder via a full duplex network connection (reads
// on one end should be matched with writes on the other).
func newConnPair() (net.Conn, net.Conn) {
	return net.Pipe()
}

func newMockFirewall() *mockFirewall {
	return &mockFirewall{
		meetsCriteria: make(map[uint64]bool),
	}
}

type mockFirewall struct {
	meetsCriteria map[uint64]bool
}

func (mf *mockFirewall) Validate(remotePeerPublicKey *ecdsa.PublicKey) error {
	if !mf.meetsCriteria[remotePeerPublicKey.X.Uint64()] {
		return fmt.Errorf("remote peer does not meet firewall criteria")
	}
	return nil
}

func (mf *mockFirewall) updatePeer(
	remotePeerPublicKey *key.NetworkPublic,
	meetsCriteria bool,
) {
	x := key.NetworkKeyToECDSAKey(remotePeerPublicKey).X.Uint64()
	mf.meetsCriteria[x] = meetsCriteria
}
