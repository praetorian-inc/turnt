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
	"strings"

	"github.com/praetorian-inc/turnt/internal/audit"
	"github.com/spf13/cobra"
)

var (
	scanTargets      string
	scanPort         int
	scanSkipDefaults bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Test relay scope (permitted peer addresses)",
	Long: `Test which peer addresses the TURN relay permits by sending CreatePermission
requests for RFC1918 ranges, loopback, cloud metadata, and custom targets.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if username == "" || password == "" {
			return fmt.Errorf("credentials required (-u/-w)")
		}

		fmt.Printf("[+] Scanning relay scope on %s...\n", serverAddr)

		// Build target list
		targets := []struct {
			IP    string
			Label string
		}{}

		if !scanSkipDefaults {
			for _, t := range audit.DefaultScanTargets {
				targets = append(targets, struct {
					IP    string
					Label string
				}{t.IP, t.Label})
			}
		}

		// Add custom targets
		if scanTargets != "" {
			for _, t := range strings.Split(scanTargets, ",") {
				t = strings.TrimSpace(t)
				if t != "" {
					targets = append(targets, struct {
						IP    string
						Label string
					}{t, "Custom"})
				}
			}
		}

		if len(targets) == 0 {
			return fmt.Errorf("no targets to scan")
		}

		results, err := audit.ScanRelayScope(serverAddr, protocol, username, password, targets, scanPort)
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}

		audit.PrintScanTable(results)

		// Summary
		allowed := 0
		for _, r := range results {
			if r.Allowed {
				allowed++
			}
		}
		fmt.Printf("\n[+] %d/%d targets reachable via relay\n", allowed, len(results))

		// Flag critical findings
		for _, r := range results {
			if r.Allowed {
				switch r.Address {
				case "169.254.169.254":
					fmt.Printf("  \033[1;31m[CRITICAL]\033[0m Cloud metadata service reachable!\n")
				case "127.0.0.1":
					fmt.Printf("  \033[1;31m[CRITICAL]\033[0m Localhost reachable!\n")
				}
			}
		}

		return nil
	},
}

func init() {
	scanCmd.Flags().StringVar(&scanTargets, "targets", "", "Additional IPs to test (comma-separated)")
	scanCmd.Flags().IntVar(&scanPort, "port", 80, "Port for CreatePermission probes")
	scanCmd.Flags().BoolVar(&scanSkipDefaults, "skip-defaults", false, "Skip default RFC1918/loopback/metadata targets")
}
