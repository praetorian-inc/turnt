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

	"github.com/praetorian-inc/turnt/internal/audit"
	"github.com/spf13/cobra"
)

var amplifyCount int

var amplifyCmd = &cobra.Command{
	Use:   "amplify",
	Short: "Measure STUN amplification ratio",
	Long: `Send minimal STUN Binding Requests and measure the response size to calculate
the amplification ratio. A ratio > 1.0 means the server can be used for
reflection/amplification attacks.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("[+] Measuring STUN amplification ratio on %s...\n", serverAddr)

		result, err := audit.TestAmplification(audit.AmplificationConfig{
			ServerAddr: serverAddr,
			Protocol:   protocol,
			Count:      amplifyCount,
		})
		if err != nil {
			return fmt.Errorf("amplification test: %w", err)
		}

		fmt.Printf("\n[+] Results:\n")
		fmt.Printf("  Requests sent:     %d\n", result.RequestsSent)
		fmt.Printf("  Responses recvd:   %d\n", result.ResponsesRecvd)
		fmt.Printf("  Request size:      %d bytes\n", result.RequestSize)
		fmt.Printf("  Avg response size: %.0f bytes\n", result.AvgResponseSize)
		fmt.Printf("  Min response size: %d bytes\n", result.MinResponseSize)
		fmt.Printf("  Max response size: %d bytes\n", result.MaxResponseSize)
		fmt.Printf("  Amplification:     %.2f:1\n", result.AmplificationRatio)

		if result.AmplificationRatio > 2.0 {
			fmt.Printf("\n  \033[33m[MEDIUM]\033[0m Amplification ratio > 2.0x\n")
			fmt.Printf("  This server could be used for STUN reflection/amplification attacks.\n")
		} else if result.AmplificationRatio > 1.0 {
			fmt.Printf("\n  \033[36m[INFO]\033[0m Amplification ratio > 1.0x (minor)\n")
		} else {
			fmt.Printf("\n  \033[32m[OK]\033[0m No significant amplification.\n")
		}

		return nil
	},
}

func init() {
	amplifyCmd.Flags().IntVar(&amplifyCount, "count", 100, "Number of Binding Requests to send")
}
