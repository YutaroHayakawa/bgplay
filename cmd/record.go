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
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/spf13/cobra"

	"github.com/YutaroHayakawa/bgplay/internal/bgputils"
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
		spec := recorder.RecorderSpec{}
		spec.PeerAddr, _ = cmd.Flags().GetString(peerAddrOpt)
		spec.PeerPort, _ = cmd.Flags().GetUint16(peerPortOpt)
		spec.LocalASN, _ = cmd.Flags().GetUint32(localASNOpt)
		spec.RouterID, _ = cmd.Flags().GetString(routerIDOpt)
		spec.FileName = args[0]
		spec.PostRecordFunc = func(msg *bgp.BGPMessage) {
			bgputils.PrintMessage(cmd.OutOrStdout(), msg)
		}

		r := recorder.New(slog.Default(), spec)

		if err := r.Record(); err != nil {
			cmd.PrintErrln("Failed start recording:", err)
		}
		defer r.Close()

		cmd.PrintErrln("Press Ctrl+C to stop.")

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		<-sigCh
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
