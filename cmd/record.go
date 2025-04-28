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
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

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
		spec := &recorder.ConnSpec{}
		spec.PeerAddr, _ = cmd.Flags().GetString(peerAddrOpt)
		spec.PeerPort, _ = cmd.Flags().GetUint16(peerPortOpt)
		spec.LocalASN, _ = cmd.Flags().GetUint32(localASNOpt)
		spec.RouterID, _ = cmd.Flags().GetString(routerIDOpt)

		var f *bgpcap.File
		f, err := bgpcap.Create(args[0])
		if err != nil {
			cmd.PrintErrf("Failed to open bgpcap file %s: %v\n", args[0], err)
			return
		}

		conn, err := recorder.Connect(spec)
		if err != nil {
			cmd.PrintErrf("Failed to connect to peer: %v\n", err)
			return
		}

		cmd.PrintErrln("Recording BGP messages")

		resultCh := make(chan error)
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			for {
				msg, err := conn.Read()
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						resultCh <- nil
						return
					}
					resultCh <- fmt.Errorf("failed to read BGP message: %w", err)
					return
				}
				if err := f.WriteMsg(msg); err != nil {
					resultCh <- fmt.Errorf("failed to write BGP message: %w", err)
					return
				}
				bgputils.PrintMessage(cmd.OutOrStdout(), msg)
			}
		}()

		select {
		case err = <-resultCh:
			if err != nil {
				cmd.PrintErrf("Encountered error while recording: %v\n", err)
			} else {
				cmd.PrintErrln("Recording completed")
			}
		case <-sigCh:
			cmd.PrintErrln("Received interrupt signal, stopping recording")
		}

		// Close BGP Connection and drain the result channel
		if err = conn.Close(); err != nil {
			cmd.PrintErrf("Failed to close connection: %v\n", err)
		}
		err = <-resultCh
		if err != nil && !errors.Is(err, net.ErrClosed) {
			cmd.PrintErrf("Encountered error while closing connection: %v\n", err)
		}

		// Close the bgpcap file
		if err = f.Close(); err != nil {
			cmd.PrintErrf("Failed to close bgpcap file: %v\n", err)
		}
	},
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
