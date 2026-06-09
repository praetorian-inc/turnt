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

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Test authentication requirements",
	Long: `Test whether the TURN server requires authentication for relay allocations.
If credentials are provided (-u/-w), also validates whether they are accepted.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("[+] Testing authentication on %s...\n\n", serverAddr)

		// Test 1: Anonymous access
		fmt.Printf("[i] Testing anonymous (unauthenticated) Allocate...\n")
		anonResult, err := audit.TestAnonymousAccess(serverAddr, protocol)
		if err != nil {
			return fmt.Errorf("anonymous access test: %w", err)
		}

		if anonResult.AnonymousAccess {
			fmt.Printf("  \033[1;31m[CRITICAL]\033[0m Server accepts unauthenticated TURN allocations!\n")
			fmt.Printf("  This means any client can create relay allocations without credentials.\n")
			fmt.Printf("  Remediation: Enable lt-cred-mech or use-auth-secret in turnserver.conf\n")
			return nil
		}

		fmt.Printf("  Authentication required (error %d: %s)\n", anonResult.ErrorCode, anonResult.ErrorReason)
		if anonResult.Realm != "" {
			fmt.Printf("  REALM: %s\n", anonResult.Realm)
		}

		// Test 2: Credential validation (if provided)
		if username != "" && password != "" {
			fmt.Printf("\n[i] Validating credentials for user '%s'...\n", username)
			credResult, err := audit.TestCredentials(serverAddr, protocol, username, password)
			if err != nil {
				return fmt.Errorf("credential test: %w", err)
			}

			if credResult.CredentialValid {
				fmt.Printf("  \033[32m[OK]\033[0m Credentials valid - allocation succeeded\n")
			} else {
				fmt.Printf("  \033[31m[FAIL]\033[0m Credentials rejected (error %d: %s)\n",
					credResult.ErrorCode, credResult.ErrorReason)
			}
		} else {
			fmt.Printf("\n[i] No credentials provided (-u/-w), skipping credential validation.\n")
		}

		return nil
	},
}
