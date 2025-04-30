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
	"io"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/YutaroHayakawa/bgplay/internal/bgputils"
	"github.com/YutaroHayakawa/bgplay/pkg/bgpcap"
	"github.com/YutaroHayakawa/bgplay/pkg/replayer"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/spf13/cobra"
)

// replayCmd represents the replay command
var replayCmd = &cobra.Command{
	Use:   "replay [FILE]",
	Args:  cobra.ExactArgs(1),
	Short: "Replays BGP messages from a file",
	Run: func(cmd *cobra.Command, args []string) {
		peerAddr, _ := cmd.Flags().GetString(peerAddrOpt)
		peerPort, _ := cmd.Flags().GetUint16(peerPortOpt)
		fileName := args[0]

		file, err := bgpcap.Open(fileName)
		if err != nil {
			cmd.PrintErrf("Error opening file: %v\n", err)
			return
		}
		defer file.Close()

		openMsg, err := file.Read()
		if err != nil {
			cmd.PrintErrf("Error reading file: %v\n", err)
			return
		}
		if openMsg.Header.Type != bgp.BGP_MSG_OPEN {
			cmd.PrintErrln("First message in the file is not OPEN")
			return
		}

		r := replayer.Dialer{
			OpenMessage: openMsg,
		}

		addr, err := netip.ParseAddr(peerAddr)
		if err != nil {
			cmd.PrintErrln("Invalid peer address:", err)
			return
		}

		conn, err := r.Connect(
			context.Background(),
			netip.AddrPortFrom(addr, peerPort),
		)
		if err != nil {
			cmd.PrintErrln("Failed to connect to peer:", err)
			return
		}
		defer conn.Close()

		bgputils.PrintMessage(os.Stdout, openMsg)

		if err := replayUpdates(file, conn); err != nil {
			cmd.PrintErrln("Failed to send OPEN message:", err)
			return
		}

		cmd.PrintErrln("Replay done. Press Ctrl-C to finish BGP session.")

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
	},
}

func replayUpdates(file *bgpcap.File, conn *replayer.Conn) error {
	for {
		msg, err := file.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
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

		if err := conn.Write(msg); err != nil {
			return err
		}

		bgputils.PrintMessage(os.Stdout, msg)
	}
}

func init() {
	rootCmd.AddCommand(replayCmd)

	replayCmd.Flags().String(peerAddrOpt, "", "Peer address")
	replayCmd.MarkFlagRequired(peerAddrOpt)

	replayCmd.Flags().Uint16(peerPortOpt, 179, "Peer port number")
}
