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
	"bufio"
	"context"
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/turnt/internal/admin"
	"github.com/praetorian-inc/turnt/internal/logger"
	"github.com/praetorian-inc/turnt/internal/socks"
	"github.com/quic-go/quic-go"
	"github.com/spf13/cobra"
)

var adminAddr string

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Connect to the TURNt admin console",
	Long:  `Connect to the controller's admin interface for managing port forwards.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Connect to admin server
		tlsConf := &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"turnt-admin"},
		}

		logger.Info("Connecting to admin server at %s", adminAddr)
		ctx := context.Background()
		conn, err := quic.DialAddr(ctx, adminAddr, tlsConf, nil)
		if err != nil {
			logger.Error("Failed to connect: %v", err)
			return fmt.Errorf("connecting to admin server: %w", err)
		}
		defer conn.CloseWithError(0, "client closing")

		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			logger.Error("Failed to open stream: %v", err)
			return fmt.Errorf("opening stream: %w", err)
		}
		defer stream.Close()

		// Create a separate stream for keepalive
		keepaliveStream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			logger.Error("Failed to open keepalive stream: %v", err)
			return fmt.Errorf("opening keepalive stream: %w", err)
		}
		defer keepaliveStream.Close()

		encoder := gob.NewEncoder(stream)
		decoder := gob.NewDecoder(stream)
		keepaliveEncoder := gob.NewEncoder(keepaliveStream)
		keepaliveDecoder := gob.NewDecoder(keepaliveStream)

		// Start keepalive goroutine
		keepaliveCtx, keepaliveCancel := context.WithCancel(context.Background())
		defer keepaliveCancel()
		go func() {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-keepaliveCtx.Done():
					return
				case <-ticker.C:
					cmd := admin.Command{
						Type: "keepalive",
					}
					if err := keepaliveEncoder.Encode(cmd); err != nil {
						logger.Error("Failed to send keepalive: %v", err)
						return
					}
					var response admin.Response
					if err := keepaliveDecoder.Decode(&response); err != nil {
						logger.Error("Failed to receive keepalive response: %v", err)
						return
					}
				}
			}
		}()

		logger.Info("Connected to admin server")
		fmt.Println("TURNt Admin Console")
		fmt.Println("Type 'help' for available commands")
		fmt.Println("Type 'exit' to quit")
		fmt.Println()

		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("> ")
			input, err := reader.ReadString('\n')
			if err != nil {
				logger.Error("Failed to read input: %v", err)
				break
			}

			input = strings.TrimSpace(input)
			if input == "" {
				continue
			}

			if input == "exit" {
				break
			}

			if input == "help" {
				fmt.Println("Available commands:")
				fmt.Println("  lportfwd add <local_port> <remote_ip>:<remote_port> - Add a new local port forward")
				fmt.Println("  lportfwd remove <local_port> - Remove a local port forward")
				fmt.Println("  lportfwd list - List all local port forwards")
				fmt.Println("  rportfwd add <port> <target> - Add a new remote port forward")
				fmt.Println("  rportfwd remove <port> - Remove a remote port forward")
				fmt.Println("  rportfwd list - List all remote port forwards")
				fmt.Println("  exit - Exit the admin console")
				continue
			}

			parts := strings.Fields(input)
			if len(parts) < 2 {
				fmt.Println("Invalid command format. Type 'help' for available commands.")
				continue
			}

			// Special handling for lportfwd and rportfwd commands
			cmdType := parts[0]
			if (parts[0] == "lportfwd" || parts[0] == "rportfwd") && len(parts) >= 2 {
				cmdType = strings.Join(parts[:2], " ")
				parts = parts[2:]
			} else {
				parts = parts[1:]
			}

			// Handle rportfwd commands
			if strings.HasPrefix(cmdType, "rportfwd") {
				switch cmdType {
				case "rportfwd add":
					if len(parts) != 2 {
						fmt.Println("Usage: rportfwd add <port> <target>")
						continue
					}
					port, err := strconv.ParseUint(parts[0], 10, 16)
					if err != nil {
						fmt.Println("Invalid port number")
						continue
					}
					cmdType = "start_rportfwd"
					adminCmdMsg := admin.Command{
						Type: cmdType,
						Payload: map[string]interface{}{
							"port":   uint16(port),
							"target": parts[1],
						},
					}
					if err := encoder.Encode(adminCmdMsg); err != nil {
						logger.Error("Failed to send command: %v", err)
						break
					}

				case "rportfwd remove":
					if len(parts) != 1 {
						fmt.Println("Usage: rportfwd remove <port>")
						continue
					}
					cmdType = "stop_rportfwd"
					adminCmdMsg := admin.Command{
						Type: cmdType,
						Payload: map[string]interface{}{
							"port": parts[0],
						},
					}
					if err := encoder.Encode(adminCmdMsg); err != nil {
						logger.Error("Failed to send command: %v", err)
						break
					}

				case "rportfwd list":
					cmdType = "list_rportfwd"
					adminCmdMsg := admin.Command{
						Type: cmdType,
					}
					if err := encoder.Encode(adminCmdMsg); err != nil {
						logger.Error("Failed to send command: %v", err)
						break
					}
				}

				var response admin.Response
				if err := decoder.Decode(&response); err != nil {
					logger.Error("Failed to receive response: %v", err)
					break
				}

				if !response.Success {
					fmt.Printf("Error: %s\n", response.Message)
				} else if response.Message != "" {
					fmt.Println(response.Message)
				} else if response.Data != nil {
					if forwards, ok := response.Data["forwards"].([]socks.PortForward); ok {
						if len(forwards) == 0 {
							fmt.Println("No active remote port forwards")
						} else {
							fmt.Println("Active remote port forwards:")
							for _, f := range forwards {
								fmt.Printf("  %s -> %s\n", f.Port, f.Target)
							}
						}
					}
				}
				continue
			}

			logger.Verbose("Sending command: Type='%s', Args=%v", cmdType, parts)
			if err := encoder.Encode(admin.Command{
				Type: cmdType,
				Args: parts,
			}); err != nil {
				logger.Error("Failed to send command: %v", err)
				break
			}

			var response admin.Response
			if err := decoder.Decode(&response); err != nil {
				logger.Error("Failed to receive response: %v", err)
				break
			}

			if !response.Success {
				fmt.Printf("Error: %s\n", response.Message)
			} else if response.Message != "" {
				fmt.Println(response.Message)
			} else if response.Data != nil {
				if forwards, ok := response.Data["forwards"].([]socks.PortForward); ok {
					if len(forwards) == 0 {
						fmt.Println("No active remote port forwards")
					} else {
						fmt.Println("Active remote port forwards:")
						for _, f := range forwards {
							fmt.Printf("  %s -> %s\n", f.Port, f.Target)
						}
					}
				}
			}
		}

		return nil
	},
}

func init() {
	adminCmd.Flags().StringVar(&adminAddr, "addr", "localhost:1337", "Admin interface address")
}
