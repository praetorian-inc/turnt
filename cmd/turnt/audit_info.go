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

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Fingerprint a TURN server",
	Long:  `Probe a TURN/STUN server to identify its implementation, version, realm, nonce format, and supported transports.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("[+] Fingerprinting %s via %s...\n\n", serverAddr, protocol)

		info, err := audit.Fingerprint(serverAddr, protocol)
		if err != nil {
			return fmt.Errorf("fingerprint failed: %w", err)
		}

		// Display results
		if info.Software != "" {
			fmt.Printf("  SOFTWARE:   %s\n", info.Software)
		} else {
			fmt.Printf("  SOFTWARE:   (not disclosed)\n")
		}

		if info.Realm != "" {
			fmt.Printf("  REALM:      %s\n", info.Realm)
		} else {
			fmt.Printf("  REALM:      (not available)\n")
		}

		if info.Nonce != "" {
			fmt.Printf("  NONCE:      %s (length: %d)\n", info.Nonce, len(info.Nonce))
		} else {
			fmt.Printf("  NONCE:      (not available)\n")
		}

		// Enumerate transports
		fmt.Printf("\n[+] Enumerating transports...\n\n")
		transports := audit.EnumerateTransports(serverAddr)
		for _, t := range transports {
			status := "\033[32mOPEN\033[0m"
			if !t.Open {
				status = "\033[31mCLOSED\033[0m"
			}
			fmt.Printf("  %s/%s:  %s\n", t.Protocol, t.Port, status)
		}

		return nil
	},
}
