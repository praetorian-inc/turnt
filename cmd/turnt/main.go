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
	"os"

	"github.com/praetorian-inc/turnt/internal/logger"
	"github.com/spf13/cobra"
)

var (
	verbose bool
	logFile string
)

var rootCmd = &cobra.Command{
	Use:   "turnt",
	Short: "TURNt - TURN server security toolkit",
	Long: `TURNt provides tools for managing TURN server credentials, controlling
WebRTC proxy sessions, administering the controller, and performing
security audits of TURN/STUN servers.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		logConfig := logger.Config{
			Level:     logger.LogInfo,
			UseStdout: true,
		}
		if verbose {
			logConfig.Level = logger.LogVerbose
		}
		if logFile != "" {
			logConfig.UseFile = true
			logConfig.LogFile = logFile
		}
		if err := logger.Init(logConfig); err != nil {
			return fmt.Errorf("failed to initialize logger: %w", err)
		}
		return nil
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		logger.Close()
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.PersistentFlags().StringVar(&logFile, "log-file", "", "Write log to file")

	rootCmd.AddCommand(credentialsCmd)
	rootCmd.AddCommand(controlCmd)
	rootCmd.AddCommand(adminCmd)
	rootCmd.AddCommand(auditCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
