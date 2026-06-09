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
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/praetorian-inc/turnt/internal/audit"
	"github.com/spf13/cobra"
)

var (
	bruteUser     string
	bruteWordlist string
	bruteThreads  int
	bruteDelay    time.Duration
)

var bruteCmd = &cobra.Command{
	Use:   "brute",
	Short: "Dictionary attack against TURN credentials",
	Long:  `Perform a dictionary attack against a known TURN username using a password wordlist.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if bruteUser == "" {
			return fmt.Errorf("--user is required")
		}
		if bruteWordlist == "" {
			return fmt.Errorf("--wordlist is required")
		}

		// Check wordlist exists
		if _, err := os.Stat(bruteWordlist); os.IsNotExist(err) {
			return fmt.Errorf("wordlist not found: %s", bruteWordlist)
		}

		fmt.Printf("[+] Starting brute-force against %s (user: %s)...\n", serverAddr, bruteUser)
		fmt.Printf("[i] Wordlist: %s | Threads: %d\n\n", bruteWordlist, bruteThreads)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Handle Ctrl+C
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigs
			fmt.Println("\n[i] Interrupted, stopping...")
			cancel()
		}()

		result, err := audit.BruteForce(ctx, audit.BruteForceConfig{
			ServerAddr: serverAddr,
			Protocol:   protocol,
			Username:   bruteUser,
			Wordlist:   bruteWordlist,
			Threads:    bruteThreads,
			Delay:      bruteDelay,
		})
		if err != nil {
			return fmt.Errorf("brute force: %w", err)
		}

		fmt.Printf("\n[+] Results:\n")
		fmt.Printf("  Attempts:  %d\n", result.Attempts)
		fmt.Printf("  Duration:  %s\n", result.Duration.Round(time.Millisecond))
		if result.Attempts > 0 {
			rate := float64(result.Attempts) / result.Duration.Seconds()
			fmt.Printf("  Rate:      %.0f attempts/sec\n", rate)
		}

		if result.Found {
			fmt.Printf("\n  \033[1;32m[FOUND]\033[0m Password: %s\n", result.Password)
		} else {
			fmt.Printf("\n  [EXHAUSTED] Password not found in wordlist.\n")
		}

		return nil
	},
}

func init() {
	bruteCmd.Flags().StringVarP(&bruteUser, "user", "U", "", "Target username")
	bruteCmd.Flags().StringVarP(&bruteWordlist, "wordlist", "W", "", "Path to password wordlist")
	bruteCmd.Flags().IntVar(&bruteThreads, "threads", 10, "Number of concurrent workers")
	bruteCmd.Flags().DurationVar(&bruteDelay, "delay", 0, "Delay between attempts per worker")
}
