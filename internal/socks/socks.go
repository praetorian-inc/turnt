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

package socks

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/armon/go-socks5"
	pion "github.com/pion/webrtc/v3"
	"github.com/praetorian-inc/turnt/internal/logger"
	"github.com/praetorian-inc/turnt/internal/webrtc"
)

type SOCKS5Server struct {
	peerConn    *pion.PeerConnection
	dnsResolver *DNSResolver
	ready       chan struct{}
	transport   *webrtc.WebRTCPeerConnection
	server      *socks5.Server
	rportfwd    *RemotePortForwardManager
}

func NewSOCKS5Server(connection *webrtc.WebRTCPeerConnection) *SOCKS5Server {
	return &SOCKS5Server{
		dnsResolver: NewDNSResolver(connection.GetPeerConnection()),
		ready:       make(chan struct{}),
		transport:   connection,
		rportfwd:    NewRemotePortForwardManager(connection),
	}
}

func (s *SOCKS5Server) Start(addr string) error {
	if err := s.dnsResolver.Start(); err != nil {
		return fmt.Errorf("failed to start DNS resolver: %v", err)
	}

	if err := s.rportfwd.Start(); err != nil {
		return fmt.Errorf("failed to start remote port forward manager: %v", err)
	}

	logger.Info("Waiting for DNS and rportfwd channels to be ready...")

	timeout := time.After(30 * time.Second)

	go func() {
		logger.Debug("Waiting for DNS resolver to be ready...")
		s.dnsResolver.WaitReady()
		logger.Debug("DNS resolver is ready, waiting for rportfwd channel...")
		// rportfwd.Start() already waits for the channel to be ready
		logger.Debug("rportfwd channel is ready, signaling all channels ready")
		close(s.ready)
	}()

	select {
	case <-s.ready:
		logger.Info("All channels ready, starting SOCKS server...")
	case <-timeout:
		logger.Error("Timeout waiting for channels to be ready, proceeding anyway...")
		logger.Error("DNS resolution may be delayed until channels are fully established")
	}

	conf := &socks5.Config{
		Resolver: NewWebRTCResolver(s.dnsResolver),
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			logger.Info("Received SOCKS5 connection request for %s://%s", network, addr)
			conn, err := s.createProxyConnection(network, addr)
			if err != nil {
				logger.Error("Failed to create proxy connection: %v", err)
				return nil, err
			}
			logger.Info("Successfully created proxy connection to %s", addr)
			return conn, nil
		},
		Logger: NewSocksLogger(),
	}

	server, err := socks5.New(conf)
	if err != nil {
		return fmt.Errorf("failed to create SOCKS5 server: %v", err)
	}
	s.server = server

	go func() {
		if err := server.ListenAndServe("tcp", addr); err != nil {
			logger.Error("SOCKS5 server error: %v", err)
		}
	}()

	return nil
}

func (s *SOCKS5Server) createProxyConnection(transport string, addr string) (net.Conn, error) {
	logger.Debug("Creating proxy connection for %s://%s", transport, addr)

	connection, err := s.newConnection(transport, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to create new connection: %v", err)
	}

	req := connectionDetails{
		NetworkType: transport,
		TargetAddr:  addr,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to encode connection request: %v", err)
	}

	channel := connection.GetChannel()
	id := connection.GetID()
	channel.OnOpen(func() {
		logger.Debug("Data channel %d opened, sending connection request to relay", id)
		if err := channel.Send(reqBytes); err != nil {
			logger.Error("Failed to send connection request on channel %s: %v", id, err)
			return
		}
		logger.Debug("Sent connection request on channel %d (%d bytes)", id, len(reqBytes))
	})

	channel.OnClose(func() {
		logger.Debug("Data channel closed for connection %d", id)
		connection.Close()
	})

	channel.OnMessage(func(msg pion.DataChannelMessage) {
		logger.Debug("Writing %d bytes to local connection", len(msg.Data))
		if _, err := connection.GetServerConnection().Write(msg.Data); err != nil {
			logger.Error("Error writing to local connection: %v", err)
			return
		}
		logger.Debug("Successfully wrote %d bytes to local connection", len(msg.Data))
	})

	go func() {
		logger.Debug("Starting server-to-client forwarding for connection %d", id)
		defer func() {
			logger.Debug("Server-to-client forwarding stopped for connection %d", id)
		}()

		buffer := make([]byte, 16384)
		for {
			logger.Verbose("Server-to-client forwarding loop for connection %d", id)
			if connection.IsClosed() {
				logger.Debug("Server-to-client forwarding stopped for connection %d as connection is closed", id)
				return
			}

			n, err := connection.GetServerConnection().Read(buffer)
			if err != nil {
				logger.Error("Server connection %d read error: %v", id, err)
				return
			}
			logger.Debug("Read %d bytes from server connection %d", n, id)

			logger.Debug("Attempting to send %d bytes on channel %d (state: %s)", n, channel.ID(), channel.ReadyState())
			if err := channel.Send(buffer[:n]); err != nil {
				logger.Error("Failed to send %d bytes on channel %d: %v", n, id, err)
				return
			}
			logger.Debug("Successfully sent %d bytes on channel %d", n, id)

			logger.Debug("Successfully wrote %d bytes to client connection %d", n, id)
		}
	}()

	return connection, nil
}

func (s *SOCKS5Server) Close() error {
	if s.rportfwd != nil {
		s.rportfwd.Close()
	}
	if s.dnsResolver != nil {
		s.dnsResolver.Close()
	}
	return nil
}

// GetRemotePortForwardManager returns the remote port forward manager for use by the admin panel
func (s *SOCKS5Server) GetRemotePortForwardManager() *RemotePortForwardManager {
	return s.rportfwd
}
