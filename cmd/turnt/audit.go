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
	"time"

	"github.com/spf13/cobra"
)

var (
	serverAddr string
	protocol   string
	username   string
	password   string
	timeout    time.Duration
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "TURN server security audit tool",
	Long: `Perform security assessments of TURN/STUN servers.

Subcommands cover fingerprinting, authentication testing, relay scope
assessment, ACL bypass verification, and protocol-level attacks.`,
}

func init() {
	auditCmd.PersistentFlags().StringVarP(&serverAddr, "server", "s", "", "TURN server address (host:port)")
	auditCmd.PersistentFlags().StringVarP(&protocol, "protocol", "p", "udp", "Transport protocol: udp, tcp, tls")
	auditCmd.PersistentFlags().StringVarP(&username, "username", "u", "", "TURN username")
	auditCmd.PersistentFlags().StringVarP(&password, "password", "w", "", "TURN password")
	auditCmd.PersistentFlags().DurationVar(&timeout, "timeout", 5*time.Second, "Per-request timeout")

	auditCmd.MarkPersistentFlagRequired("server")

	auditCmd.AddCommand(infoCmd)
	auditCmd.AddCommand(authCmd)
	auditCmd.AddCommand(bruteCmd)
	auditCmd.AddCommand(scanCmd)
	auditCmd.AddCommand(bypassCmd)
	auditCmd.AddCommand(floodCmd)
	auditCmd.AddCommand(memoryleakCmd)
	auditCmd.AddCommand(amplifyCmd)
}
