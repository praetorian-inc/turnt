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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/pion/webrtc/v3"
	"github.com/praetorian-inc/turnt/internal/logger"
	"github.com/praetorian-inc/turnt/internal/utils"
)

// RelayPortListener represents an active remote port-forward
type RelayPortListener struct {
	GUID     string
	Port     string
	Listener net.Listener
	Conn     net.Conn
}

type Relay struct {
	peerConn    *webrtc.PeerConnection
	verbose     bool
	started     bool
	dnsResolver *DNSResolver
	forwards    map[string]*RelayPortListener
	mu          sync.RWMutex
}

func NewRelay(peerConn *webrtc.PeerConnection) *Relay {
	return &Relay{
		peerConn:    peerConn,
		started:     false,
		dnsResolver: NewDNSResolver(peerConn),
		forwards:    make(map[string]*RelayPortListener),
	}
}

func (r *Relay) Start() error {
	if r.started {
		return fmt.Errorf("relay already started")
	}

	r.peerConn.OnDataChannel(func(channel *webrtc.DataChannel) {
		logger.Debug("New data channel: %s (state: %s, ID: %d)",
			channel.Label(), channel.ReadyState().String(), *channel.ID())

		if channel.Label() == "dns" {
			logger.Debug("Setting DNS channel in resolver")
			r.dnsResolver.channel = channel
			channel.OnOpen(func() {
				logger.Debug("DNS channel opened")
				close(r.dnsResolver.ready)
			})
			channel.OnMessage(func(msg webrtc.DataChannelMessage) {
				var request DNSRequest
				if err := json.Unmarshal(msg.Data, &request); err != nil {
					logger.Error("Failed to decode DNS request: %v", err)
					return
				}

				logger.Debug("Received DNS resolution request for hostname: %s", request.Hostname)
				r.dnsResolver.HandleDNSRequest(request)
			})
			return
		}

		if channel.Label() == "rportfwd" {
			logger.Info("Received rportfwd control channel")
			channel.OnMessage(func(msg webrtc.DataChannelMessage) {
				var request RemotePortForwardRequest
				if err := json.Unmarshal(msg.Data, &request); err != nil {
					logger.Error("Failed to decode rportfwd message: %v", err)
					return
				}

				switch request.Type {
				case "start_rportfwd":
					r.handleStartForward(request, channel)
				case "stop_rportfwd":
					r.handleStopForward(request)
				}
			})
			return
		}

		// Handle rportfwd connection channels
		if len(channel.Label()) > 9 && channel.Label()[:9] == "rportfwd:" {
			guid := channel.Label()[9:]
			r.handleForwardConnection(guid, channel)
			return
		}

		channel.OnOpen(func() {
			logger.Debug("Data channel opened: %s", channel.Label())
		})

		channel.OnMessage(func(msg webrtc.DataChannelMessage) {
			if err := r.handleInitialConnection(channel, msg); err != nil {
				logger.Error("Failed to handle initial connection: %v", err)
				channel.Close()
				return
			}
		})

		channel.OnClose(func() {
			logger.Debug("Data channel closed: %s", channel.Label())
		})
	})

	r.started = true
	return nil
}

func (r *Relay) handleStartForward(request RemotePortForwardRequest, channel *webrtc.DataChannel) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.forwards[request.GUID]; exists {
		logger.Error("Forward already exists for GUID: %s", request.GUID)
		response := RemotePortForwardResponse{
			Type:    "rportfwd_response",
			GUID:    request.GUID,
			Success: false,
			Error:   "forward already exists",
		}
		responseBytes, _ := json.Marshal(response)
		channel.Send(responseBytes)
		return
	}

	// Create listener on the specified port
	listener, err := net.Listen("tcp", ":"+request.Port)
	if err != nil {
		logger.Error("Failed to listen on port %s: %v", request.Port, err)
		response := RemotePortForwardResponse{
			Type:    "rportfwd_response",
			GUID:    request.GUID,
			Success: false,
			Error:   fmt.Sprintf("failed to listen: %v", err),
		}
		responseBytes, _ := json.Marshal(response)
		channel.Send(responseBytes)
		return
	}

	forward := &RelayPortListener{
		GUID:     request.GUID,
		Port:     request.Port,
		Listener: listener,
	}
	r.forwards[request.GUID] = forward

	response := RemotePortForwardResponse{
		Type:    "rportfwd_response",
		GUID:    request.GUID,
		Success: true,
	}
	responseBytes, _ := json.Marshal(response)
	channel.Send(responseBytes)

	logger.Info("Started remote port forward for GUID %s on port %s", request.GUID, request.Port)

	// Start accepting connections
	go r.acceptConnections(request.GUID, listener)
}

func (r *Relay) acceptConnections(guid string, listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				continue
			}
			logger.Error("Failed to accept connection for GUID %s: %v", guid, err)
			return
		}

		logger.Info("Accepted new connection from %s for GUID %s", conn.RemoteAddr(), guid)

		// Create a new data channel for this connection
		channel, err := r.peerConn.CreateDataChannel(fmt.Sprintf("rportfwd:%s", guid), &webrtc.DataChannelInit{
			Ordered:    utils.PTR(true),
			Negotiated: utils.PTR(false),
		})
		if err != nil {
			logger.Error("Failed to create data channel for GUID %s: %v", guid, err)
			conn.Close()
			continue
		}

		// Store the connection in the forward
		r.mu.Lock()
		if forward, exists := r.forwards[guid]; exists {
			forward.Conn = conn
		}
		r.mu.Unlock()

		// Set up the data channel handlers
		handlers := createHandlers(conn, channel)
		channel.OnMessage(handlers.onMessage)
		channel.OnClose(handlers.onClose)

		// Start reading from the connection
		go r.handleConnectionRead(conn, channel)
	}
}

func (r *Relay) handleStopForward(request RemotePortForwardRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if forward, exists := r.forwards[request.GUID]; exists {
		if forward.Listener != nil {
			forward.Listener.Close()
		}
		if forward.Conn != nil {
			forward.Conn.Close()
		}
		delete(r.forwards, request.GUID)
		logger.Info("Stopped remote port forward for GUID: %s", request.GUID)
	}
}

func (r *Relay) handleForwardConnection(guid string, channel *webrtc.DataChannel) {
	r.mu.RLock()
	forward, exists := r.forwards[guid]
	r.mu.RUnlock()

	if !exists {
		logger.Error("Received connection for unknown GUID: %s", guid)
		channel.Close()
		return
	}

	logger.Info("New connection received for remote port forward GUID: %s", guid)

	// Set up the data channel handlers
	handlers := createHandlers(forward.Conn, channel)
	channel.OnMessage(handlers.onMessage)
	channel.OnClose(handlers.onClose)

	// Start reading from the connection
	go r.handleConnectionRead(forward.Conn, channel)
}

func (r *Relay) handleInitialConnection(channel *webrtc.DataChannel, msg webrtc.DataChannelMessage) error {
	var req connectionDetails
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		return fmt.Errorf("failed to decode connection request: %v", err)
	}

	logger.Debug("Received connection info: channel %s (byte length: %d)", channel.Label(), len(msg.Data))
	netConn, err := utils.DialTarget(string(req.NetworkType), req.TargetAddr)
	if err != nil {
		return fmt.Errorf("failed to establish connection: %v", err)
	}

	logger.Debug("Connection mapping stored for channel %s to %s", channel.Label(), req.TargetAddr)

	r.setupConnection(channel, netConn)

	go r.handleConnectionRead(netConn, channel)

	return nil
}

func createHandlers(netConn net.Conn, channel *webrtc.DataChannel) (handlers struct {
	onMessage func(webrtc.DataChannelMessage)
	onClose   func()
}) {
	handlers.onMessage = func(msg webrtc.DataChannelMessage) {
		logger.Debug("Received %d bytes on channel %s (first few: % x)",
			len(msg.Data), channel.Label(), msg.Data[:min(len(msg.Data), 16)])

		if _, err := netConn.Write(msg.Data); err != nil {
			logger.Error("Error writing to target connection: %v", err)
			netConn.Close()
			channel.Close()
			return
		}

		logger.Debug("Successfully wrote %d bytes to target connection", len(msg.Data))
	}

	handlers.onClose = func() {
		logger.Debug("Channel %s closed, cleaning up connection", channel.Label())
		netConn.Close()
	}

	return handlers
}

func (r *Relay) setupConnection(channel *webrtc.DataChannel, netConn net.Conn) {
	handlers := createHandlers(netConn, channel)
	channel.OnMessage(handlers.onMessage)
	channel.OnClose(handlers.onClose)
}

func (r *Relay) handleConnectionRead(netConn net.Conn, channel *webrtc.DataChannel) {
	buffer := make([]byte, 16384)
	id := *channel.ID()
	logger.Debug("Starting read loop for connection to %s on channel %d", netConn.RemoteAddr(), id)

	for {
		n, err := netConn.Read(buffer)
		if err != nil {
			if err == io.EOF {
				logger.Debug("End of file reached for connection to %s", netConn.RemoteAddr())
			} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			} else {
				logger.Error("Error reading from connection to %s: %v", netConn.RemoteAddr(), err)
			}
			return
		}

		logger.Debug("Read %d bytes from remote connection to %s", n, netConn.RemoteAddr())
		logger.Debug("Sending %d bytes over data channel to controller for %d connection", n, id)

		err = channel.Send(buffer[:n])
		if err != nil {
			logger.Error("Error sending to data channel %d: %v", id, err)
			return
		}
	}
}

func (r *Relay) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, forward := range r.forwards {
		if forward.Listener != nil {
			forward.Listener.Close()
		}
		if forward.Conn != nil {
			forward.Conn.Close()
		}
	}
	r.forwards = make(map[string]*RelayPortListener)

	r.dnsResolver.Close()
}
