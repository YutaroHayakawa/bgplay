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
	"github.com/spf13/cobra"

	"github.com/YutaroHayakawa/bgplay/pkg/bgpcap"
	"github.com/YutaroHayakawa/bgplay/pkg/reporter"
)

// reportCmd represents the report command
var reportCmd = &cobra.Command{
	Use:   "report [FILE]",
	Args:  cobra.ExactArgs(1),
	Short: "Read recorded BGP messages from file and display them",
	Run: func(cmd *cobra.Command, args []string) {
		f, err := bgpcap.Open(args[0])
		if err != nil {
			cmd.PrintErrf("Error opening file: %v\n", err)
			return
		}
		defer f.Close()

		if err := reporter.Report(cmd.OutOrStdout(), f); err != nil {
			cmd.PrintErrf("Error reading file: %v\n", err)
			return
		}
	},
}

func init() {
	rootCmd.AddCommand(reportCmd)
}
