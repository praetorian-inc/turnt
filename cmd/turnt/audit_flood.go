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
	"time"

	"github.com/praetorian-inc/turnt/internal/audit"
	"github.com/spf13/cobra"
)

var (
	floodMax   int
	floodDelay time.Duration
)

var floodCmd = &cobra.Command{
	Use:   "flood",
	Short: "Test allocation quota enforcement",
	Long: `Create TURN allocations until the server returns 486 (Allocation Quota Reached)
or the maximum count is reached. Tests whether per-user and total quotas are enforced.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if username == "" || password == "" {
			return fmt.Errorf("credentials required (-u/-w)")
		}

		fmt.Printf("[+] Testing allocation quotas on %s (max: %d)...\n", serverAddr, floodMax)

		result, err := audit.TestAllocationFlood(audit.FloodConfig{
			ServerAddr: serverAddr,
			Protocol:   protocol,
			Username:   username,
			Password:   password,
			MaxAllocs:  floodMax,
			Delay:      floodDelay,
		})
		if err != nil {
			return fmt.Errorf("flood test: %w", err)
		}

		fmt.Printf("\n[+] Results:\n")
		fmt.Printf("  Allocations created: %d\n", result.Allocations)
		fmt.Printf("  Duration:            %s\n", result.Duration.Round(time.Millisecond))

		if result.QuotaHit {
			fmt.Printf("  Quota enforced:      \033[32mYES\033[0m (server returned 486 at %d allocations)\n", result.Allocations)
		} else if result.Allocations >= floodMax {
			fmt.Printf("  Quota enforced:      \033[1;33m[MEDIUM]\033[0m NO (created %d allocations without quota)\n", result.Allocations)
			fmt.Printf("\n  The server does not enforce per-user allocation quotas.\n")
			fmt.Printf("  Remediation: Set user-quota and total-quota in turnserver.conf\n")
		} else {
			fmt.Printf("  Stopped:             %d %s\n", result.LastError, result.LastReason)
		}

		return nil
	},
}

func init() {
	floodCmd.Flags().IntVar(&floodMax, "max", 1000, "Maximum allocations to attempt")
	floodCmd.Flags().DurationVar(&floodDelay, "delay", 100*time.Millisecond, "Delay between allocations")
}
