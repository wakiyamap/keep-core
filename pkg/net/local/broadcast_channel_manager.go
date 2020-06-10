package local

import (
	"context"
	"sync"
	"time"

	"github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/net/key"
	"github.com/keep-network/keep-core/pkg/net/retransmission"
)

var broadcastChannelsMutex sync.Mutex
var broadcastChannels map[string][]*localChannel

// getBroadcastChannel returns a BroadcastChannel designed to mediate between local
// participants. It delivers all messages sent to the channel through its
// receive channels. RecvChan on a LocalChannel creates a new receive channel
// that is returned to the caller, so that all receive channels can receive
// the message.
func getBroadcastChannel(name string, staticKey *key.NetworkPublic) net.BroadcastChannel {
	broadcastChannelsMutex.Lock()
	defer broadcastChannelsMutex.Unlock()
	if broadcastChannels == nil {
		broadcastChannels = make(map[string][]*localChannel)
	}

	localChannels, exists := broadcastChannels[name]
	if !exists {
		localChannels = make([]*localChannel, 0)
		broadcastChannels[name] = localChannels
	}

	identifier := randomLocalIdentifier()
	channel := &localChannel{
		name:                 name,
		identifier:           &identifier,
		staticKey:            staticKey,
		messageHandlersMutex: sync.Mutex{},
		messageHandlers:      make([]*messageHandler, 0),
		unmarshalersMutex:    sync.Mutex{},
		unmarshalersByType:   make(map[string]func() net.TaggedUnmarshaler),
		retransmissionTicker: retransmission.NewTimeTicker(
			context.Background(), 50*time.Millisecond,
		),
	}
	broadcastChannels[name] = append(broadcastChannels[name], channel)

	return channel
}

func broadcastMessage(name string, message net.Message) error {
	broadcastChannelsMutex.Lock()
	targetChannels := broadcastChannels[name]
	broadcastChannelsMutex.Unlock()

	for _, targetChannel := range targetChannels {
		targetChannel.deliver(message)
	}

	return nil
}
