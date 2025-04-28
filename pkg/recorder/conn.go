package recorder

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/netip"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/YutaroHayakawa/bgplay/internal/bgputils"
)

type Conn struct {
	spec            ConnSpec
	conn            net.Conn
	peerOpenMsg     *bgp.BGPMessage
	cancelKeepAlive context.CancelFunc
}

type ConnSpec struct {
	PeerAddr string
	PeerPort uint16
	LocalASN uint32
	RouterID string
}

func Connect(spec *ConnSpec) (*Conn, error) {
	if spec == nil {
		return nil, fmt.Errorf("spec is not provided")
	}
	b := &Conn{
		spec: *spec,
	}
	if err := b.establish(); err != nil {
		return nil, fmt.Errorf("cannot establish BGP session: %w", err)
	}
	b.startKeepAlive()
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

	// We're passive. Expect peer OPEN.
	msg, err := b.expectMessage(bgp.BGP_MSG_OPEN)
	if err != nil {
		return err
	}
	peerOpen := msg.Body.(*bgp.BGPOpen)

	// Store peer open message for later use
	b.peerOpenMsg = msg

	// Derive our OPEN message from the peer's OPEN message and send it.
	msg = b.deriveOpenFromPeer(peerOpen)
	if err = bgputils.WriteBGPMessage(b.conn, msg); err != nil {
		return err
	}

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

			// Send KEEPALIVE message to the peer
			if err := bgputils.WriteBGPMessage(
				b.conn,
				bgp.NewBGPKeepAliveMessage(),
			); err != nil {
				return
			}
		}
	}()

	b.cancelKeepAlive = cancel
}

func (b *Conn) Read() (*bgp.BGPMessage, error) {
	if b.peerOpenMsg != nil {
		msg := b.peerOpenMsg
		b.peerOpenMsg = nil
		return msg, nil
	}
	for {
		msg, err := bgputils.ReadBGPMessage(b.conn)
		if err != nil {
			return nil, err
		}
		switch msg.Header.Type {
		case bgp.BGP_MSG_UPDATE:
			return msg, nil
		case bgp.BGP_MSG_KEEPALIVE:
			// Ignore KEEPALIVE messages. Reread.
			continue
		case bgp.BGP_MSG_NOTIFICATION:
			// Return error on notification
			return nil, bgputils.NewNotificationError(msg.Body.(*bgp.BGPNotification))
		default:
			return nil, fmt.Errorf("unexpected message type (%d)", msg.Header.Type)
		}
	}
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

func (b *Conn) deriveOpenFromPeer(peerOpen *bgp.BGPOpen) *bgp.BGPMessage {
	// RFC4893
	var myAS uint16
	if b.spec.LocalASN > math.MaxUint16 {
		myAS = bgp.AS_TRANS
	} else {
		myAS = uint16(b.spec.LocalASN)
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
				myCaps = append(myCaps, bgp.NewCapFourOctetASNumber(b.spec.LocalASN))
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
		b.spec.RouterID,
		[]bgp.OptionParameterInterface{
			bgp.NewOptionParameterCapability(myCaps),
		},
	)
}
