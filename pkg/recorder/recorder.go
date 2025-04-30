package recorder

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/YutaroHayakawa/bgplay/internal/bgputils"
	"github.com/YutaroHayakawa/bgplay/pkg/bgpcap"
)

var (
	errField  = "error"
	typeField = "type"
)

type Recorder struct {
	spec   RecorderSpec
	logger *slog.Logger

	f           *bgpcap.File
	conn        net.Conn
	peerOpenMsg *bgp.BGPMessage
	cancel      context.CancelFunc
}

type RecorderSpec struct {
	PeerAddr string
	PeerPort uint16
	LocalASN uint32
	RouterID string
	FileName string
}

func New(logger *slog.Logger, spec RecorderSpec) *Recorder {
	return &Recorder{
		spec:   spec,
		logger: logger,
	}
}

func (r *Recorder) Record() error {
	f, err := bgpcap.Create(r.spec.FileName)
	if err != nil {
		return fmt.Errorf("failed to open bgpcap file %s: %w", r.spec.FileName, err)
	}
	r.f = f

	if err := r.establish(); err != nil {
		return fmt.Errorf("cannot establish BGP session: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel

	r.startKeepAlive(ctx)
	r.startRecordUpdates(ctx)

	return nil
}

func (r *Recorder) establish() error {
	addr, err := netip.ParseAddr(r.spec.PeerAddr)
	if err != nil {
		return fmt.Errorf("invalid PeerAddr: %w", err)
	}

	conn, err := net.Dial("tcp", netip.AddrPortFrom(addr, r.spec.PeerPort).String())
	if err != nil {
		return fmt.Errorf("failed to connect to peer: %w", err)
	}
	r.conn = conn

	// We're passive. Expect peer OPEN.
	msg, err := bgputils.ExpectMessage(r.conn, bgp.BGP_MSG_OPEN)
	if err != nil {
		return err
	}
	peerOpen := msg.Body.(*bgp.BGPOpen)

	// Store peer open message for later use
	r.peerOpenMsg = msg

	// Derive our OPEN message from the peer's OPEN message and send it.
	msg = r.deriveOpenFromPeer(peerOpen)
	if err = bgputils.WriteBGPMessage(r.conn, msg); err != nil {
		return err
	}

	// Send out KEEPALIVE message to the peer.
	msg = bgp.NewBGPKeepAliveMessage()
	if err = bgputils.WriteBGPMessage(r.conn, msg); err != nil {
		return err
	}

	// Expect peer KEEPALIVE.
	msg, err = bgputils.ExpectMessage(r.conn, bgp.BGP_MSG_KEEPALIVE)
	if err != nil {
		return err
	}

	return nil
}

func (r *Recorder) startKeepAlive(ctx context.Context) {
	go func() {
		r.logger.Info("Start sending KEEPALIVE messages")
		defer r.logger.Info("Stop sending KEEPALIVE messages")

		interval := r.peerOpenMsg.Body.(*bgp.BGPOpen).HoldTime / 3
		for {
			ch := time.After(time.Duration(interval) * time.Second)
			select {
			case <-ctx.Done():
				return
			case <-ch:
			}

			// Send KEEPALIVE message to the peer
			if err := bgputils.WriteBGPMessage(
				r.conn,
				bgp.NewBGPKeepAliveMessage(),
			); err != nil {
				r.logger.Error("Failed to send KEEPALIVE", "error", err)
				return
			}
		}
	}()
}

func (r *Recorder) startRecordUpdates(ctx context.Context) {
	go func() {
		r.logger.Info("Start recording BGP messages")
		defer r.logger.Info("Stop recording BGP messages")

		if err := r.f.WriteMsg(r.peerOpenMsg); err != nil {
			r.logger.Error("Failed to write BGP message", errField, err)
			return
		}
		for {
			r.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

			msg, err := bgputils.ReadBGPMessage(r.conn)
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					if ctx.Err() == nil {
						// Timeout. Ignore and continue.
						continue
					} else {
						// Context is done. Return.
						return
					}
				}
				if errors.Is(err, net.ErrClosed) {
					// Connection close is expected. Return.
					return
				}
				r.logger.Error("Failed to read BGP message", errField, err)
				return
			}
			switch msg.Header.Type {
			case bgp.BGP_MSG_UPDATE:
				// Handle UPDATE messages
			case bgp.BGP_MSG_KEEPALIVE:
				// Ignore KEEPALIVE messages. Reread.
				continue
			case bgp.BGP_MSG_NOTIFICATION:
				// Return error on notification
				err := bgputils.NewNotificationError(msg.Body.(*bgp.BGPNotification))
				r.logger.Error("Received NOTIFICATION message", errField, err)
				return
			default:
				r.logger.Error("Received unexpected message type", typeField, msg.Header.Type)
				return
			}
			if err := r.f.WriteMsg(msg); err != nil {
				r.logger.Error("Failed to write BGP message", errField, err)
				return
			}
		}
	}()
}

func (r *Recorder) Close() error {
	if r.conn != nil {
		if err := r.conn.Close(); err != nil {
			return fmt.Errorf("failed to close connection: %w", err)
		}
		r.conn = nil
	}
	if r.cancel != nil {
		r.cancel()
	}
	return nil
}

func (r *Recorder) deriveOpenFromPeer(peerOpen *bgp.BGPOpen) *bgp.BGPMessage {
	// RFC4893
	var myAS uint16
	if r.spec.LocalASN > math.MaxUint16 {
		myAS = bgp.AS_TRANS
	} else {
		myAS = uint16(r.spec.LocalASN)
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
				myCaps = append(myCaps, bgp.NewCapFourOctetASNumber(r.spec.LocalASN))
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
		r.spec.RouterID,
		[]bgp.OptionParameterInterface{
			bgp.NewOptionParameterCapability(myCaps),
		},
	)
}
