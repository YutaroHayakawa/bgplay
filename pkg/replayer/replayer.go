package replayer

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/YutaroHayakawa/bgplay/internal/bgputils"
)

type Dialer struct {
	OpenMessage *bgp.BGPMessage
}

type Conn struct {
	mu          sync.Mutex
	conn        net.Conn
	peerOpenMsg *bgp.BGPMessage
	cancel      context.CancelFunc
}

func (d *Dialer) Connect(ctx context.Context, ap netip.AddrPort) (*Conn, error) {
	c := &Conn{}

	if d.OpenMessage == nil {
		return nil, fmt.Errorf("OpenMessage is not provided")
	}

	if err := c.establish(ap, d.OpenMessage); err != nil {
		return nil, fmt.Errorf("cannot establish BGP session: %w", err)
	}

	ctx, c.cancel = context.WithCancel(ctx)
	c.startKeepAlive(ctx)

	return c, nil
}

func (c *Conn) Write(msg *bgp.BGPMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("connection is not established")
	}

	if err := bgputils.WriteBGPMessage(c.conn, msg); err != nil {
		return fmt.Errorf("failed to write BGP message: %w", err)
	}

	return nil
}

func (c *Conn) Close() error {
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			return fmt.Errorf("failed to close connection: %w", err)
		}
	}
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

func (c *Conn) establish(addrPort netip.AddrPort, openMsg *bgp.BGPMessage) error {
	conn, err := net.Dial("tcp", addrPort.String())
	if err != nil {
		return fmt.Errorf("failed to connect to peer: %w", err)
	}
	c.conn = conn

	// Send OPEN message.
	if err = bgputils.WriteBGPMessage(conn, openMsg); err != nil {
		return err
	}

	// Expect peer OPEN
	msg, err := bgputils.ExpectMessage(conn, bgp.BGP_MSG_OPEN)
	if err != nil {
		return err
	}
	c.peerOpenMsg = msg

	// Send out KEEPALIVE message to the peer.
	msg = bgp.NewBGPKeepAliveMessage()
	if err = bgputils.WriteBGPMessage(conn, msg); err != nil {
		return err
	}

	// Expect peer KEEPALIVE.
	if _, err = bgputils.ExpectMessage(conn, bgp.BGP_MSG_KEEPALIVE); err != nil {
		return err
	}

	return nil
}

func (c *Conn) startKeepAlive(ctx context.Context) {
	go func() {
		interval := c.peerOpenMsg.Body.(*bgp.BGPOpen).HoldTime / 3
		for {
			ch := time.After(time.Duration(interval) * time.Second)
			select {
			case <-ctx.Done():
				return
			case <-ch:
			}

			c.mu.Lock()

			// Send KEEPALIVE message to the peer
			if err := bgputils.WriteBGPMessage(
				c.conn,
				bgp.NewBGPKeepAliveMessage(),
			); err != nil {
				c.mu.Unlock()
				return
			}

			c.mu.Unlock()
		}
	}()
}
