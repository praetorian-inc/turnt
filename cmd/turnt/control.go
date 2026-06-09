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
	"sync"
	"syscall"

	pion "github.com/pion/webrtc/v3"
	"github.com/praetorian-inc/turnt/internal/admin"
	"github.com/praetorian-inc/turnt/internal/config"
	"github.com/praetorian-inc/turnt/internal/logger"
	"github.com/praetorian-inc/turnt/internal/socks"
	"github.com/praetorian-inc/turnt/internal/webrtc"
	"github.com/spf13/cobra"
)

var (
	controlConfigPath string
	controlSocksAddr  string
)

var controlCmd = &cobra.Command{
	Use:   "control",
	Short: "Start the WebRTC SOCKS5 proxy controller",
	Long:  `Establish a WebRTC peer connection via TURN servers and start a SOCKS5 proxy.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("[+] Starting SOCKS5 proxy (controller)...")

		cfg, err := config.LoadConfig(controlConfigPath)
		if err != nil {
			logger.Error("Error loading config: %v", err)
			return fmt.Errorf("loading config: %w", err)
		}

		// Initialize admin server
		adminServer := admin.NewServer()

		// Initialize local port forward manager with SOCKS configuration
		lpfManager := admin.NewPortForwardManager("127.0.0.1:1080")

		// Register handlers
		adminServer.RegisterHandler("lportfwd add", lpfManager.HandleAdd)
		adminServer.RegisterHandler("lportfwd remove", lpfManager.HandleRemove)
		adminServer.RegisterHandler("lportfwd list", lpfManager.HandleList)

		// Register remote port forward handlers
		adminServer.RegisterHandler("list_rportfwd", adminServer.HandleRemotePortForward)
		adminServer.RegisterHandler("start_rportfwd", adminServer.HandleRemotePortForward)
		adminServer.RegisterHandler("stop_rportfwd", adminServer.HandleRemotePortForward)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if err := adminServer.Start(ctx); err != nil {
			logger.Error("Failed to start admin server: %v", err)
			return fmt.Errorf("starting admin server: %w", err)
		}
		defer adminServer.Stop()

		fmt.Println("[i] Creating WebRTC peer connection...")
		peerConn, err := webrtc.NewPeerConnection(cfg.ICEServers)
		if err != nil {
			logger.Error("Error creating peer connection: %v", err)
			return fmt.Errorf("creating peer connection: %w", err)
		}

		if peerConn == nil {
			logger.Error("Peer connection is nil despite no error returned")
			return fmt.Errorf("peer connection is nil")
		}

		pc := peerConn.GetPeerConnection()
		if pc == nil {
			logger.Error("Underlying PeerConnection is nil")
			return fmt.Errorf("underlying PeerConnection is nil")
		}

		exiting := make(chan os.Signal, 1)
		signal.Notify(exiting, syscall.SIGINT, syscall.SIGTERM)

		socksServer := socks.NewSOCKS5Server(peerConn)

		// Set the SOCKS server in the admin server
		adminServer.SetSOCKS5Server(socksServer)

		shuttingDown := false
		shutdownMutex := sync.Mutex{}

		pc.OnConnectionStateChange(func(state pion.PeerConnectionState) {
			logger.Info("WebRTC connection state changed: %s", state.String())

			switch state {
			case pion.PeerConnectionStateNew:
				logger.Info("WebRTC connection initialized")
			case pion.PeerConnectionStateConnecting:
				logger.Info("WebRTC connection establishing...")
			case pion.PeerConnectionStateConnected:
				logger.Info("WebRTC connection established successfully")
			case pion.PeerConnectionStateDisconnected:
				logger.Error("WebRTC connection lost")
				logger.Error("Due to the connectionless nature of this setup, recovery is unlikely - please restart and re-pair")
				shutdownMutex.Lock()
				if shuttingDown {
					shutdownMutex.Unlock()
					return
				}
				shuttingDown = true
				shutdownMutex.Unlock()

				if socksServer != nil {
					socksServer.Close()
				}
				if pc != nil {
					pc.Close()
				}
				logger.Info("Shutdown complete, exiting...")
				os.Exit(1)
			case pion.PeerConnectionStateFailed:
				logger.Error("WebRTC connection failed and cannot recover")
				logger.Error("Please restart and re-pair the connection")
				shutdownMutex.Lock()
				if shuttingDown {
					shutdownMutex.Unlock()
					return
				}
				shuttingDown = true
				shutdownMutex.Unlock()

				if socksServer != nil {
					socksServer.Close()
				}
				if pc != nil {
					pc.Close()
				}
				logger.Info("Shutdown complete, exiting...")
				os.Exit(1)
			case pion.PeerConnectionStateClosed:
				logger.Info("WebRTC connection closed normally")
			}
		})

		pc.OnICECandidate(func(candidate *pion.ICECandidate) {
			if candidate != nil {
				logger.Info("New ICE candidate: %s", candidate.String())
			} else {
				logger.Info("ICE gathering complete")
			}
		})

		fmt.Println("[i] Creating WebRTC offer...")
		encodedOffer, err := peerConn.CreateOfferWithCredentials(cfg)
		if err != nil {
			return fmt.Errorf("creating offer: %w", err)
		}

		fmt.Println("\n===== BASE64 ENCODED OFFER PAYLOAD =====")
		fmt.Println(encodedOffer)
		fmt.Println("========================================")

		fmt.Println("\n[i] Waiting for answer...")
		var base64Answer string
		for {
			_, err := fmt.Scanln(&base64Answer)
			if err != nil {
				logger.Error("Error reading answer: %v", err)
				fmt.Println("Please try again:")
				continue
			}
			if base64Answer != "" {
				break
			}
			fmt.Println("Empty answer received, please try again:")
		}

		fmt.Println("[i] Processing answer...")
		if err := peerConn.HandleCompressedAnswer(base64Answer); err != nil {
			logger.Error("Error processing answer: %v", err)
			return fmt.Errorf("processing answer: %w", err)
		}

		fmt.Println("[+] WebRTC connection established!")

		if err := socksServer.Start(controlSocksAddr); err != nil {
			logger.Error("Failed to start SOCKS5 server: %v", err)
			return fmt.Errorf("starting SOCKS5 server: %w", err)
		}

		logger.Info("SOCKS5 server listening on %s", controlSocksAddr)

		select {
		case <-exiting:
			shutdownMutex.Lock()
			if shuttingDown {
				shutdownMutex.Unlock()
				return nil
			}
			shuttingDown = true
			shutdownMutex.Unlock()

			logger.Info("Received shutdown signal from operator, closing WebRTC connection with relay...")
			if socksServer != nil {
				socksServer.Close()
			}
			if pc != nil {
				pc.Close()
			}
			logger.Info("Shutdown complete, exiting...")
			return nil
		}
	},
}

func init() {
	controlCmd.Flags().StringVar(&controlConfigPath, "config", "", "Path to YAML config file with TURN credentials")
	controlCmd.Flags().StringVar(&controlSocksAddr, "socks", "127.0.0.1:1080", "SOCKS5 server address")
	controlCmd.MarkFlagRequired("config")
}
