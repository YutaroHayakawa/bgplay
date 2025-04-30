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

	"github.com/YutaroHayakawa/bgplay/internal/bgputils"
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
		spec := replayer.ReplayerSpec{}
		spec.PeerAddr, _ = cmd.Flags().GetString(peerAddrOpt)
		spec.PeerPort, _ = cmd.Flags().GetUint16(peerPortOpt)
		spec.FileName = args[0]
		spec.PostReplayFunc = func(msg *bgp.BGPMessage) {
			bgputils.PrintMessage(cmd.OutOrStdout(), msg)
		}

		r := replayer.New(slog.Default(), spec)

		if err := r.Replay(); err != nil {
			cmd.PrintErrf("Failed to replay BGP messages: %v\n", err)
			return
		}
		defer r.Close()

		cmd.PrintErrln("Replay done. Press Ctrl-C to finish BGP session.")

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		<-sigCh
	},
}

func init() {
	rootCmd.AddCommand(replayCmd)

	replayCmd.Flags().String(peerAddrOpt, "", "Peer address")
	replayCmd.MarkFlagRequired(peerAddrOpt)

	replayCmd.Flags().Uint16(peerPortOpt, 179, "Peer port number")
}
