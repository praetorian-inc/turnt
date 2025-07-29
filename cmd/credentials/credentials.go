// Copyright 2025 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/praetorian-inc/turnt/internal/msteams"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "credentials",
	Short: "Manage credentials for various services",
}

var (
	outputFile string
)

var teamsCmd = &cobra.Command{
	Use:   "msteams",
	Short: "Get Microsoft Teams TURN credentials",
	Run: func(cmd *cobra.Command, args []string) {
		creds, err := msteams.GetTurnCredentials()
		if err != nil {
			log.Fatalf("Failed to get Teams credentials: %v", err)
		}

		if err := msteams.SaveConfig(creds, outputFile); err != nil {
			log.Fatalf("Failed to save config: %v", err)
		}

		fmt.Printf("Successfully retrieved Teams credentials and saved to %s\n", outputFile)
	},
}

func main() {
	teamsCmd.Flags().StringVarP(&outputFile, "output", "o", "config.yaml", "output file path")
	rootCmd.AddCommand(teamsCmd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
