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
	"io"
	"os"

	"github.com/YutaroHayakawa/bgplay/internal/bgputils"
	"github.com/spf13/cobra"
)

// reportCmd represents the report command
var reportCmd = &cobra.Command{
	Use:   "report [FILE]",
	Args:  cobra.ExactArgs(1),
	Short: "Read recorded BGP messages from file and display them",
	Run: func(cmd *cobra.Command, args []string) {
		f, err := os.Open(args[0])
		if err != nil {
			cmd.PrintErrf("Error opening file: %v\n", err)
			return
		}
		defer f.Close()

		for {
			msg, err := bgputils.ReadBGPMessage(f)
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				cmd.PrintErrf("Error reading BGP message: %v\n", err)
				return
			}
			bgputils.PrintMessage(os.Stdout, msg)
		}
	},
}

func init() {
	rootCmd.AddCommand(reportCmd)
}
