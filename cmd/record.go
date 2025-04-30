/*
Copyright © 2025 Yutaro Hayakawa

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/spf13/cobra"

	"github.com/YutaroHayakawa/bgplay/internal/bgputils"
	"github.com/YutaroHayakawa/bgplay/pkg/bgpcap"
	"github.com/YutaroHayakawa/bgplay/pkg/recorder"
)

var (
	peerAddrOpt = "peer-addr"
	peerPortOpt = "peer-port"
	localASNOpt = "local-asn"
	routerIDOpt = "router-id"
	writeOpt    = "write"
)

// recordCmd represents the record command
var recordCmd = &cobra.Command{
	Use:   "record [FILE]",
	Short: "Record BGP Messages",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		peerAddr, _ := cmd.Flags().GetString(peerAddrOpt)
		peerPort, _ := cmd.Flags().GetUint16(peerPortOpt)
		localASN, _ := cmd.Flags().GetUint32(localASNOpt)
		routerID, _ := cmd.Flags().GetString(routerIDOpt)
		fileName := args[0]

		id, err := netip.ParseAddr(routerID)
		if err != nil {
			cmd.PrintErrln("Invalid router ID:", err)
			return
		}

		r := recorder.Dialer{
			AS: localASN,
			ID: id,
		}

		addr, err := netip.ParseAddr(peerAddr)
		if err != nil {
			cmd.PrintErrln("Invalid peer address:", err)
			return
		}

		conn, err := r.Connect(context.Background(), netip.AddrPortFrom(addr, peerPort))
		if err != nil {
			cmd.PrintErrln("Failed start recording:", err)
			return
		}
		defer conn.Close()

		file, err := bgpcap.Create(fileName)
		if err != nil {
			cmd.PrintErrln("Failed to create file:", err)
			return
		}
		defer file.Close()

		cmd.PrintErrln("Recording started. Press Ctrl+C to stop.")

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		if err := recordUpdates(sigCh, conn, file); err != nil {
			cmd.PrintErrln("Error recording BGP messages:", err)
		}
	},
}

func recordUpdates(sigCh chan os.Signal, conn *recorder.Conn, file *bgpcap.File) error {
	for {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

		msg, err := conn.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				select {
				case <-sigCh:
					return nil
				default:
					continue
				}
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		switch msg.Header.Type {
		case bgp.BGP_MSG_OPEN:
			// Handle OPEN messages
		case bgp.BGP_MSG_UPDATE:
			// Handle UPDATE messages
		case bgp.BGP_MSG_KEEPALIVE:
			// Ignore KEEPALIVE messages. Reread.
			continue
		case bgp.BGP_MSG_NOTIFICATION:
			// Return an error for NOTIFICATION messages
			return bgputils.NewNotificationError(msg.Body.(*bgp.BGPNotification))
		default:
			return fmt.Errorf("unexpected message type: %d", msg.Header.Type)
		}

		if err := file.Write(msg); err != nil {
			return err
		}

		bgputils.PrintMessage(os.Stdout, msg)
	}
}

func init() {
	rootCmd.AddCommand(recordCmd)

	recordCmd.Flags().String(peerAddrOpt, "", "Peer address")
	recordCmd.MarkFlagRequired(peerAddrOpt)

	recordCmd.Flags().Uint16(peerPortOpt, 179, "Peer port number")

	recordCmd.Flags().Uint32(localASNOpt, 0, "Local AS number")
	recordCmd.MarkFlagRequired(localASNOpt)

	recordCmd.Flags().String(routerIDOpt, "", "Router ID")
	recordCmd.MarkFlagRequired(routerIDOpt)
}
