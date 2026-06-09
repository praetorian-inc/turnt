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

var (
	memleakOverflow int
	memleakCount    int
)

var memoryleakCmd = &cobra.Command{
	Use:   "memoryleak",
	Short: "Test for memory disclosure via malformed TLV",
	Long: `Send STUN messages with TLV attributes where the claimed length exceeds
the actual data. If the server reads beyond the attribute boundary, it may
include heap memory in its response (similar to Heartbleed).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("[+] Testing memory disclosure on %s...\n", serverAddr)

		result, err := audit.TestMemoryLeak(audit.MemoryLeakConfig{
			ServerAddr: serverAddr,
			Protocol:   protocol,
			Username:   username,
			Password:   password,
			Overflow:   memleakOverflow,
			Count:      memleakCount,
		})
		if err != nil {
			return fmt.Errorf("memory leak test: %w", err)
		}

		fmt.Printf("\n[+] Results:\n")
		fmt.Printf("  Probes sent:       %d\n", result.ProbesSent)
		fmt.Printf("  Responses recvd:   %d\n", result.ResponsesRecvd)
		fmt.Printf("  Baseline size:     %d bytes\n", result.BaselineSize)
		fmt.Printf("  Max response size: %d bytes\n", result.MaxResponseSize)
		fmt.Printf("  Extra bytes:       %d\n", result.ExtraBytes)

		if result.LeakDetected {
			fmt.Printf("\n  \033[1;31m[HIGH]\033[0m Memory disclosure detected!\n")
			fmt.Printf("  Server responses contain %d extra bytes beyond normal size.\n", result.ExtraBytes)
			fmt.Printf("  This may contain heap data from other sessions.\n")
			if result.SampleHex != "" {
				fmt.Printf("\n  Sample leaked data (hex):\n%s\n", result.SampleHex)
			}
		} else {
			fmt.Printf("\n  \033[32m[OK]\033[0m No memory disclosure detected.\n")
		}

		return nil
	},
}

func init() {
	memoryleakCmd.Flags().IntVar(&memleakOverflow, "overflow", 256, "Extra bytes to claim beyond actual data")
	memoryleakCmd.Flags().IntVar(&memleakCount, "count", 10, "Number of probes to send")
}
