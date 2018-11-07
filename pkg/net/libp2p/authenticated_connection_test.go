package libp2p

import (
	"context"
	crand "crypto/rand"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	protoio "github.com/gogo/protobuf/io"

	keepnet "github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/net/gen/pb"
	"github.com/keep-network/keep-core/pkg/net/key"
	"github.com/keep-network/keep-core/pkg/net/security/handshake"

	basichost "github.com/libp2p/go-libp2p-blankhost"
	libp2pcrypto "github.com/libp2p/go-libp2p-crypto"
	host "github.com/libp2p/go-libp2p-host"
	metrics "github.com/libp2p/go-libp2p-metrics"
	peer "github.com/libp2p/go-libp2p-peer"
	pstore "github.com/libp2p/go-libp2p-peerstore"
	pstoremem "github.com/libp2p/go-libp2p-peerstore/pstoremem"
	swarm "github.com/libp2p/go-libp2p-swarm"
	tptu "github.com/libp2p/go-libp2p-transport-upgrader"
	tcpt "github.com/libp2p/go-tcp-transport"
	ma "github.com/multiformats/go-multiaddr"
	msmux "github.com/whyrusleeping/go-smux-multistream"
	yamux "github.com/whyrusleeping/go-smux-yamux"
)

func TestPinnedAndMessageKeyMismatch(t *testing.T) {
	initiatorStaticKey, initiatorPeerID := testStaticKeyAndID(t)
	responderStaticKey, responderPeerID := testStaticKeyAndID(t)
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
		return
	}(initiatorConn, initiatorPeerID, initiatorStaticKey, responderPeerID, responderStaticKey)

	_, err := newAuthenticatedInboundConnection(
		responderConn,
		responderPeerID,
		responderStaticKey,
		"",
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

	initiatorAct1, err := handshake.InitiateHandshake()
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

	maliciousInitiatorStaticKey, maliciousInitiatorPeerID := testStaticKeyAndID(t)
	signedAct3Message, err := maliciousInitiatorStaticKey.Sign(act3WireMessage)
	if err != nil {
		t.Fatal(err)
	}

	act3Envelope := &pb.HandshakeEnvelope{
		Message:   act3WireMessage,
		PeerID:    []byte(maliciousInitiatorPeerID),
		Signature: signedAct3Message,
	}

	if err := initiatorConnectionWriter.WriteMsg(act3Envelope); err != nil {
		t.Fatal(err)
	}
}

func TestHandshakeRoundTrip(t *testing.T) {
	_, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Connect the initiator and responder sessions
	authnInboundConn, authnOutboundConn := connectInitiatorAndResponderFull(t)

	msg := []byte("brown fox blue tail")
	go func(authnOutboundConn *authenticatedConnection, msg []byte) {
		if _, err := authnOutboundConn.Write(msg); err != nil {
			t.Fatal(err)
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

func connectInitiatorAndResponderFull(t *testing.T) (*authenticatedConnection, *authenticatedConnection) {
	initiatorStaticKey, initiatorPeerID := testStaticKeyAndID(t)
	responderStaticKey, responderPeerID := testStaticKeyAndID(t)
	initiatorConn, responderConn := newConnPair()

	var (
		done              = make(chan struct{})
		initiatorErr      error
		authnOutboundConn *authenticatedConnection
	)
	go func(
		initiatorConn net.Conn,
		initiatorPeerID peer.ID,
		initiatorStaticKey libp2pcrypto.PrivKey,
		responderPeerID peer.ID,
	) {
		authnOutboundConn, initiatorErr = newAuthenticatedOutboundConnection(
			initiatorConn,
			initiatorPeerID,
			initiatorStaticKey,
			responderPeerID,
		)
		done <- struct{}{}
	}(initiatorConn, initiatorPeerID, initiatorStaticKey, responderPeerID)

	authnInboundConn, err := newAuthenticatedInboundConnection(
		responderConn,
		responderPeerID,
		responderStaticKey,
		"",
	)
	if err != nil {
		t.Fatalf("failed to connect initiator with responder [%v]", err)
	}

	// handshake is done, and we'll know if the outbound failed
	<-done

	if initiatorErr != nil {
		t.Fatal(initiatorErr)
	}

	return authnInboundConn, authnOutboundConn
}

func testStaticKeyAndID(t *testing.T) (libp2pcrypto.PrivKey, peer.ID) {
	staticKey, err := key.GenerateStaticNetworkKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := peer.IDFromPrivateKey(staticKey)
	if err != nil {
		t.Fatal(err)
	}
	return staticKey, peerID
}

// Connect an initiator and responder via a full duplex network connection (reads
// on one end should be matched with writes on the other).
func newConnPair() (net.Conn, net.Conn) {
	return net.Pipe()
}

func newTestProvider(ctx context.Context, identity *identity, host host.Host) (*provider, error) {
	cm, err := newChannelManager(ctx, identity, host)
	if err != nil {
		return nil, err
	}

	provider := &provider{
		channelManagr: cm,
		identity:      identity,
		host:          host,
	}
	return provider, nil
}

func newTestChnanel(name string, provider *provider) (*channel, error) {
	broadcastChannel, err := provider.ChannelFor(name)
	if err != nil {
		return nil, err
	}

	if err := broadcastChannel.RegisterUnmarshaler(
		func() keepnet.TaggedUnmarshaler { return &testMessage{} },
	); err != nil {
		return nil, err
	}

	ch, ok := broadcastChannel.(*channel)
	if !ok {
		return nil, fmt.Errorf("unexpected channel type")
	}
	return ch, nil
}

func TestMaliciousInitiatorAfterHandshake(t *testing.T) {
	ctx := context.Background()

	responderHost := basichost.NewBlankHost(GenSwarm(t, ctx))
	initiatorHost := basichost.NewBlankHost(GenSwarm(t, ctx))
	// defer responderHost.Close()
	// defer initiatorHost.Close()

	initiatorIdentity, err := createIdentity(initiatorHost.Peerstore().PrivKey(initiatorHost.ID()))
	if err != nil {
		t.Fatal(err)
	}
	initiatorProvider, err := newTestProvider(ctx, initiatorIdentity, initiatorHost)
	if err != nil {
		t.Fatal(err)
	}

	// Connect the initiator and responder sessions - this exercises the handshake
	responderPeerInfo := responderHost.Peerstore().PeerInfo(responderHost.ID())
	fmt.Printf("peer %+v connecting to peer %+v\n", initiatorHost.ID(), responderPeerInfo.ID)
	if err := initiatorHost.Connect(ctx, responderPeerInfo); err != nil {
		t.Fatal(err)
	}

	initiatorChannel, err := newTestChnanel("testchannel", initiatorProvider)
	if err != nil {
		t.Fatal(err)
	}

	responderIdentity, err := createIdentity(responderHost.Peerstore().PrivKey(responderHost.ID()))
	if err != nil {
		t.Fatal(err)
	}
	responderProvider, err := newTestProvider(ctx, responderIdentity, responderHost)
	if err != nil {
		t.Fatal(err)
	}
	responderChannel, err := newTestChnanel("testchannel", responderProvider)
	if err != nil {
		t.Fatal(err)
	}

	// honestPayload := "I did know once, only I've sort of forgotten."
	maliciousPayload := "You never can tell with bees."
	// Create and publish message with a signature created with other key than
	// sender's...
	_, err = key.GenerateStaticNetworkKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// envelope, err := initiatorChannel.sealEnvelope(nil, &testMessage{Payload: maliciousPayload})
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// adversarySignature, err := initiatorIdentity.privKey.Sign(envelope.Message)
	// adversarySignature, err := adversaryKey.Sign(envelope.Message)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// envelope.Signature = adversarySignature

	// envelopeBytes, err := envelope.Marshal()
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// initiatorChannel.pubsub.Publish(initiatorChannel.name, envelopeBytes)
	err = initiatorChannel.Send(&testMessage{Payload: maliciousPayload})
	if err != nil {
		t.Fatal(err)
	}

	// Check if the message with correct signature has been properly delivered
	// and if the message with incorrect signature has been dropped...
	recvChan := make(chan keepnet.Message)
	if err := responderChannel.Recv(keepnet.HandleMessageFunc{
		Type: "test",
		Handler: func(msg keepnet.Message) error {
			fmt.Println("never made it here")
			recvChan <- msg
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}

	ensureNonMaliciousMessage := func(t *testing.T, msg keepnet.Message) error {
		fmt.Println("not called")
		testPayload, ok := msg.Payload().(*testMessage)
		if !ok {
			return fmt.Errorf(
				"expected: payload type string\ngot:   payload type [%v]",
				testPayload,
			)
		}
		fmt.Printf("Payload: %+v\n", testPayload)

		// if maliciousPayload != testPayload.Payload {
		// 	return fmt.Errorf(
		// 		"expected: message payload [%s]\ngot:   payload [%s]",
		// 		honestPayload,
		// 		testPayload.Payload,
		// 	)
		// }
		return nil
	}

	for {
		select {
		case msg := <-recvChan:
			fmt.Printf("MSG: %+v\n", msg)
			if err := ensureNonMaliciousMessage(t, msg); err != nil {
				t.Fatal(err)
			}
			// Ensure all messages are flushed before exiting
		case <-time.After(6 * time.Second):
			t.Fatal(fmt.Errorf("didn't finish in time"))
			// return
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

// GenSwarm generates a new test swarm.
func GenSwarm(t *testing.T, ctx context.Context) *swarm.Swarm {
	privKey, id := testStaticKeyAndID(t)
	pubKey := privKey.GetPublic()

	authenticatedTransport, err := newAuthenticatedTransport(privKey)
	if err != nil {
		t.Fatal(err)
	}

	ps := pstoremem.NewPeerstore()
	ps.AddPubKey(id, pubKey)
	ps.AddPrivKey(id, privKey)
	s := swarm.NewSwarm(ctx, id, ps, metrics.NewBandwidthCounter())

	stMuxer := msmux.NewBlankTransport()
	stMuxer.AddTransport("/yamux/1.0.0", yamux.DefaultTransport)

	tcpTransport := tcpt.NewTCPTransport(&tptu.Upgrader{
		Secure: authenticatedTransport,
		Muxer:  stMuxer,
	})

	if err := s.AddTransport(tcpTransport); err != nil {
		t.Fatal(err)
	}

	maddr, err := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/0")
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Listen(maddr); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("listening at %+v\n", s.ListenAddresses())

	s.Peerstore().AddAddrs(id, s.ListenAddresses(), pstore.PermanentAddrTTL)

	return s
}
