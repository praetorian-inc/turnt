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
	bypassTarget string
	bypassPort   int
)

var bypassCmd = &cobra.Command{
	Use:   "bypass",
	Short: "Test ACL bypass techniques",
	Long: `Test whether denied-peer-ip rules can be circumvented using alternative
address representations (IPv4-mapped IPv6, zero addresses, IPv6 loopback).

Tests for known vulnerabilities:
  - CVE-2026-27624: IPv4-mapped IPv6 bypass (::ffff:x.x.x.x)
  - CVE-2020-26262: Alternative loopback representations (0.0.0.0, ::, ::1)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if username == "" || password == "" {
			return fmt.Errorf("credentials required (-u/-w)")
		}

		fmt.Printf("[+] Testing ACL bypass for %s on %s...\n", bypassTarget, serverAddr)

		result, err := audit.TestACLBypass(serverAddr, protocol, username, password, bypassTarget, bypassPort)
		if err != nil {
			return fmt.Errorf("bypass test: %w", err)
		}

		audit.PrintScanTable(result.Results)

		if result.BypassFound {
			fmt.Printf("\n  \033[1;31m[CRITICAL]\033[0m ACL bypass detected!\n")
			fmt.Printf("  The server's denied-peer-ip rules can be circumvented using\n")
			fmt.Printf("  alternative address representations. Direct access to %s is\n", bypassTarget)
			fmt.Printf("  denied, but alternative encodings are permitted.\n")
			fmt.Printf("\n  Remediation:\n")
			fmt.Printf("  - Upgrade coturn to >= 4.9.0 (fixes CVE-2026-27624)\n")
			fmt.Printf("  - Add: denied-peer-ip=::ffff:0.0.0.0-::ffff:255.255.255.255\n")
		} else {
			// Check if everything is allowed (no ACLs at all)
			allAllowed := true
			for _, r := range result.Results {
				if !r.Allowed {
					allAllowed = false
					break
				}
			}
			if allAllowed {
				fmt.Printf("\n  [INFO] All address representations are permitted.\n")
				fmt.Printf("  This may indicate no denied-peer-ip rules are configured.\n")
			} else {
				fmt.Printf("\n  \033[32m[OK]\033[0m No ACL bypass detected for %s.\n", bypassTarget)
			}
		}

		return nil
	},
}

func init() {
	bypassCmd.Flags().StringVar(&bypassTarget, "target", "127.0.0.1", "Base target IP to test bypasses against")
	bypassCmd.Flags().IntVar(&bypassPort, "port", 80, "Port for CreatePermission probes")
}
