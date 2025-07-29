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
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	pion "github.com/pion/webrtc/v3"
	"github.com/praetorian-inc/turnt/internal/logger"
	"github.com/praetorian-inc/turnt/internal/socks"
	"github.com/praetorian-inc/turnt/internal/webrtc"
)

func main() {
	offerFlag := flag.String("offer", "", "Base64 encoded offer payload")
	verboseFlag := flag.Bool("verbose", false, "Enable verbose logging")
	logFileFlag := flag.String("log-file", "", "Path to write log output (optional)")
	offerFileFlag := flag.String("offer-file", "", "Path to write offer/answer data (optional)")
	flag.Parse()

	logConfig := logger.Config{
		Level:     logger.LogInfo,
		UseStdout: true,
		UseFile:   *logFileFlag != "",
		LogFile:   *logFileFlag,
	}
	if *verboseFlag {
		logConfig.Level = logger.LogVerbose
	}
	if err := logger.Init(logConfig); err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
	}
	defer logger.Close()

	if *offerFlag == "" {
		fmt.Println("[-] Error: No offer payload provided")
		fmt.Println("Usage: ./relay -offer \"<Base64_Offer>\" [-log-file <path>] [-offer-file <path>] [-verbose]")
		return
	}

	if *offerFileFlag != "" {
		os.Remove(*offerFileFlag)
		offerFile, err := os.Create(*offerFileFlag)
		if err != nil {
			fmt.Printf("[-] Error creating offer file: %v\n", err)
			return
		}
		defer offerFile.Close()
		fmt.Fprintf(offerFile, "Offer: %s\n", *offerFlag)
	}

	fmt.Println("[+] Starting Relay...")

	offerPayload, err := webrtc.DecodeCompressedOffer(*offerFlag)
	if err != nil {
		fmt.Printf("[-] Error decoding compressed offer: %v\n", err)
		return
	}

	if len(offerPayload.ICEServers) == 0 {
		fmt.Println("[-] Error: No ICE servers found in the offer")
		return
	}

	logger.Debug("Found %d ICE server(s) in the offer", len(offerPayload.ICEServers))
	for i, server := range offerPayload.ICEServers {
		logger.Debug("   Server %d: %v", i+1, server.URLs)
	}

	fmt.Println("[i] Creating WebRTC peer connection...")
	peerConn, err := webrtc.NewPeerConnection(offerPayload.ICEServers)
	if err != nil {
		fmt.Printf("[-] Error creating peer connection: %v\n", err)
		return
	}

	if peerConn == nil {
		fmt.Println("[-] Error: Peer connection is nil despite no error returned")
		return
	}

	pc := peerConn.GetPeerConnection()
	if pc == nil {
		fmt.Println("[-] Error: Underlying PeerConnection is nil")
		return
	}

	exiting := make(chan os.Signal, 1)
	signal.Notify(exiting, syscall.SIGINT, syscall.SIGTERM)

	relay := socks.NewRelay(pc)

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

			if relay != nil {
				relay.Close()
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

			if relay != nil {
				relay.Close()
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

	if err := relay.Start(); err != nil {
		fmt.Printf("[-] Error starting relay: %v\n", err)
		return
	}

	fmt.Println("[i] Generating answer...")
	compressedAnswer, err := peerConn.HandleOfferGenerateAnswer(offerPayload)
	if err != nil {
		fmt.Printf("[-] Error generating answer: %v\n", err)
		return
	}

	if *offerFileFlag != "" {
		os.Remove(*offerFileFlag)
		offerFile, err := os.Create(*offerFileFlag)
		if err != nil {
			fmt.Printf("[-] Error creating offer file for answer: %v\n", err)
		} else {
			defer offerFile.Close()
			fmt.Fprintf(offerFile, "Answer: %s\n", compressedAnswer)
		}
	}

	fmt.Println("Answer:", compressedAnswer)
	fmt.Println("[i] Waiting for WebRTC connection to establish...")

	select {
	case <-exiting:
		shutdownMutex.Lock()
		if shuttingDown {
			shutdownMutex.Unlock()
			return
		}
		shuttingDown = true
		shutdownMutex.Unlock()

		logger.Info("Received shutdown signal from operator, closing WebRTC connection with controller...")
		if relay != nil {
			relay.Close()
		}
		if pc != nil {
			pc.Close()
		}
		logger.Info("Shutdown complete, exiting...")
		os.Exit(0)
	}
}
