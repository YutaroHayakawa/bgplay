package recorder

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/YutaroHayakawa/bgplay/internal/bgputils"
)

type Dialer struct {
	AS uint32
	ID netip.Addr
}

type Conn struct {
	mu          sync.Mutex
	conn        net.Conn
	readOpen    bool
	peerOpenMsg *bgp.BGPMessage
	cancel      context.CancelFunc
}

func (d *Dialer) Connect(ctx context.Context, addrPort netip.AddrPort) (*Conn, error) {
	c := &Conn{}
	if err := c.establish(d.AS, d.ID, addrPort); err != nil {
		return nil, fmt.Errorf("cannot establish BGP session: %w", err)
	}
	ctx, c.cancel = context.WithCancel(ctx)
	c.startKeepAlive(ctx)
	return c, nil
}

func (c *Conn) Read() (*bgp.BGPMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, fmt.Errorf("connection is not established")
	}

	if !c.readOpen {
		c.readOpen = true
		return c.peerOpenMsg, nil
	}

	msg, err := bgputils.ReadBGPMessage(c.conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read BGP message: %w", err)
	}

	return msg, nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *Conn) Close() error {
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			return fmt.Errorf("failed to close connection: %w", err)
		}
		c.conn = nil
	}
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

func (c *Conn) establish(as uint32, id netip.Addr, addrPort netip.AddrPort) error {
	conn, err := net.Dial("tcp", addrPort.String())
	if err != nil {
		return fmt.Errorf("failed to connect to peer: %w", err)
	}
	c.conn = conn

	// We're passive. Expect peer OPEN.
	msg, err := bgputils.ExpectMessage(c.conn, bgp.BGP_MSG_OPEN)
	if err != nil {
		return err
	}
	peerOpen := msg.Body.(*bgp.BGPOpen)

	// Store peer open message for later use
	c.peerOpenMsg = msg

	// Derive our OPEN message from the peer's OPEN message and send it.
	msg = c.deriveOpenFromPeer(as, id, peerOpen)
	if err = bgputils.WriteBGPMessage(c.conn, msg); err != nil {
		return err
	}

	// Send out KEEPALIVE message to the peer.
	msg = bgp.NewBGPKeepAliveMessage()
	if err = bgputils.WriteBGPMessage(c.conn, msg); err != nil {
		return err
	}

	// Expect peer KEEPALIVE.
	if _, err = bgputils.ExpectMessage(c.conn, bgp.BGP_MSG_KEEPALIVE); err != nil {
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

			// Send KEEPALIVE message to the peer
			if err := bgputils.WriteBGPMessage(
				c.conn,
				bgp.NewBGPKeepAliveMessage(),
			); err != nil {
				return
			}
		}
	}()
}

func (c *Conn) deriveOpenFromPeer(as uint32, id netip.Addr, peerOpen *bgp.BGPOpen) *bgp.BGPMessage {
	// RFC4893
	var myAS uint16
	if as > math.MaxUint16 {
		myAS = bgp.AS_TRANS
	} else {
		myAS = uint16(as)
	}

	// Handle capabilities
	var myCaps []bgp.ParameterCapabilityInterface
	for _, opt := range peerOpen.OptParams {
		capOpt, ok := opt.(*bgp.OptionParameterCapability)
		if !ok {
			continue
		}
		for _, capa := range capOpt.Capability {
			switch c := capa.(type) {
			case *bgp.CapRouteRefresh:
			case *bgp.CapEnhancedRouteRefresh:
			case *bgp.CapRouteRefreshCisco:
				// We don't advertise any route.
			case *bgp.CapCarryingLabelInfo:
				// Obsoleted by RFC8277: In RFC3107, this
				// feature was controlled by a BGP Capability
				// Code that has never been implemented and is
				// now deprecated.
			case *bgp.CapGracefulRestart:
			case *bgp.CapLongLivedGracefulRestart:
				// We will never restart gracefully or help peer
				// restart gracefully.
			case *bgp.CapFQDN:
			case *bgp.CapSoftwareVersion:
				// These are purely cosmetic and doesn't affect the
				// operation of the BGP session. We don't need to
				// advertise it.
			case *bgp.CapMultiProtocol:
				// Just let the peer advertise anything they want.
				myCaps = append(myCaps, c)
			case *bgp.CapExtendedNexthop:
				// Just let the peer advertise anything they want.
				myCaps = append(myCaps, c)
			case *bgp.CapFourOctetASNumber:
				// We always support 4-octet AS number. When
				// the peer supports it.
				myCaps = append(myCaps, bgp.NewCapFourOctetASNumber(as))
			case *bgp.CapAddPath:
				// If the peer wish to send the ADD-PATH
				// routes, let them do it.
				tuples := []*bgp.CapAddPathTuple{}
				for _, tuple := range c.Tuples {
					if tuple.Mode == bgp.BGP_ADD_PATH_RECEIVE {
						// If the peer is receive only, we
						// don't need to send it as we don't
						// send any route.
						continue
					}
					tuples = append(tuples, bgp.NewCapAddPathTuple(
						tuple.RouteFamily,
						bgp.BGP_ADD_PATH_RECEIVE,
					))
				}
				if len(tuples) > 0 {
					myCaps = append(myCaps, bgp.NewCapAddPath(tuples))
				}
			}
		}
	}
	return bgp.NewBGPOpenMessage(
		myAS,
		math.MaxUint16, // Maximum possible hold time
		id.String(),
		[]bgp.OptionParameterInterface{
			bgp.NewOptionParameterCapability(myCaps),
		},
	)
}
