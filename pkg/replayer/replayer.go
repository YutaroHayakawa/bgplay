package replayer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/YutaroHayakawa/bgplay/internal/bgputils"
	"github.com/YutaroHayakawa/bgplay/pkg/bgpcap"
)

type Conn struct {
	spec            ConnSpec
	f               *bgpcap.File
	peerOpenMsg     *bgp.BGPMessage
	cancelKeepAlive context.CancelFunc

	// KeepAlive and Update messages might be sent in parallel
	connMutex sync.Mutex
	conn      net.Conn
}

type ConnSpec struct {
	PeerAddr string
	PeerPort uint16
}

func Replay(connSpec *ConnSpec, f *bgpcap.File) (*Conn, error) {
	if f == nil {
		return nil, fmt.Errorf("bgpcap file is not provided")
	}
	b := &Conn{
		spec: *connSpec,
		f:    f,
	}
	if err := b.establish(); err != nil {
		return nil, fmt.Errorf("cannot establish BGP session: %w", err)
	}

	b.startKeepAlive()

	if err := b.sendUpdates(); err != nil {
		return nil, fmt.Errorf("failed to send updates: %w", err)
	}

	return b, nil
}

func (b *Conn) establish() error {
	addr, err := netip.ParseAddr(b.spec.PeerAddr)
	if err != nil {
		return fmt.Errorf("invalid PeerAddr: %w", err)
	}

	conn, err := net.Dial("tcp", netip.AddrPortFrom(addr, b.spec.PeerPort).String())
	if err != nil {
		return fmt.Errorf("failed to connect to peer: %w", err)
	}
	b.conn = conn

	// Read the first message from the file
	msg, err := b.f.ReadMsg()
	if err != nil {
		return fmt.Errorf("failed to read BGP message from file: %w", err)
	}

	// Check if the message is an OPEN message
	if msg.Header.Type != bgp.BGP_MSG_OPEN {
		return fmt.Errorf("the first message in the bgpcap file must be OPEN message to replay, got %d", msg.Header.Type)
	}

	// Send OPEN message.
	if err = bgputils.WriteBGPMessage(b.conn, msg); err != nil {
		return err
	}

	// Expect peer OPEN
	msg, err = b.expectMessage(bgp.BGP_MSG_OPEN)
	if err != nil {
		return err
	}
	b.peerOpenMsg = msg

	// Send out KEEPALIVE message to the peer.
	msg = bgp.NewBGPKeepAliveMessage()
	if err = bgputils.WriteBGPMessage(b.conn, msg); err != nil {
		return err
	}

	// Expect peer KEEPALIVE.
	msg, err = b.expectMessage(bgp.BGP_MSG_KEEPALIVE)
	if err != nil {
		return err
	}

	return nil
}

func (b *Conn) sendUpdates() error {
	for {
		msg, err := b.f.ReadMsg()
		if err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Println("End of file reached")
				return nil
			}
			return fmt.Errorf("failed to read BGP message from file: %w", err)
		}

		if msg.Header.Type != bgp.BGP_MSG_UPDATE {
			// Skip non-UPDATE messages
			continue
		}

		b.connMutex.Lock()

		// Send UPDATE message to the peer
		if err := bgputils.WriteBGPMessage(b.conn, msg); err != nil {
			b.connMutex.Unlock()
			return fmt.Errorf("failed to send UPDATE message: %w", err)
		}

		b.connMutex.Unlock()
	}
}

func (b *Conn) startKeepAlive() {
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		interval := b.peerOpenMsg.Body.(*bgp.BGPOpen).HoldTime / 3
		for {
			ch := time.After(time.Duration(interval) * time.Second)
			select {
			case <-ctx.Done():
				return
			case <-ch:
			}

			b.connMutex.Lock()

			// Send KEEPALIVE message to the peer
			if err := bgputils.WriteBGPMessage(
				b.conn,
				bgp.NewBGPKeepAliveMessage(),
			); err != nil {
				b.connMutex.Unlock()
				return
			}

			b.connMutex.Unlock()
		}
	}()

	b.cancelKeepAlive = cancel
}

func (m *Conn) Close() error {
	if m.conn != nil {
		if err := m.conn.Close(); err != nil {
			return fmt.Errorf("failed to close connection: %w", err)
		}
		m.conn = nil
	}
	if m.cancelKeepAlive != nil {
		m.cancelKeepAlive()
	}
	return nil
}

func maybeNotificationError(msg *bgp.BGPMessage) (*bgp.BGPMessage, error) {
	notif, ok := msg.Body.(*bgp.BGPNotification)
	if !ok {
		return msg, nil
	}
	return nil, bgputils.NewNotificationError(notif)
}

func (b *Conn) expectMessage(msgType int) (*bgp.BGPMessage, error) {
	msg, err := bgputils.ReadBGPMessage(b.conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read BGP message: %w", err)
	}
	if msg.Header.Type != uint8(msgType) {
		return maybeNotificationError(msg)
	}
	return msg, nil
}
