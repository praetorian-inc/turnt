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
	"time"

	"github.com/google/uuid"
	pion "github.com/pion/webrtc/v3"
	"github.com/praetorian-inc/turnt/internal/logger"
	"github.com/praetorian-inc/turnt/internal/utils"
	turntwebrtc "github.com/praetorian-inc/turnt/internal/webrtc"
)

// PortForward represents an active remote port forward
type PortForward struct {
	GUID   string
	Port   string
	Target string
}

// RemotePortForwardManager manages remote port forwards
type RemotePortForwardManager struct {
	peerConn      *turntwebrtc.WebRTCPeerConnection
	channel       *pion.DataChannel
	guidToForward map[string]*PortForward
	portToForward map[uint16]*PortForward
	mu            sync.RWMutex
	started       bool
	ready         chan struct{}
}

// NewRemotePortForwardManager creates a new remote port forward manager
func NewRemotePortForwardManager(peerConn *turntwebrtc.WebRTCPeerConnection) *RemotePortForwardManager {
	manager := &RemotePortForwardManager{
		peerConn:      peerConn,
		guidToForward: make(map[string]*PortForward),
		portToForward: make(map[uint16]*PortForward),
		ready:         make(chan struct{}),
	}

	return manager
}

// Start initializes the remote port forward manager
func (m *RemotePortForwardManager) Start() error {
	if m.started {
		return fmt.Errorf("remote port forward manager already started")
	}

	// Create the rportfwd control channel
	channel, err := m.peerConn.CreateDataChannel("rportfwd", &pion.DataChannelInit{
		Ordered:    utils.PTR(true),
		Negotiated: utils.PTR(false),
	})
	if err != nil {
		return fmt.Errorf("failed to create rportfwd channel: %v", err)
	}

	m.channel = channel

	// Wait for the channel to be ready
	go func() {
		logger.Debug("Waiting for rportfwd channel to be ready...")
		for {
			if m.channel.ReadyState() == pion.DataChannelStateOpen {
				logger.Debug("rportfwd channel is ready")
				close(m.ready)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	// Set up message handler for the control channel
	m.channel.OnMessage(func(msg pion.DataChannelMessage) {
		var response RemotePortForwardResponse
		if err := json.Unmarshal(msg.Data, &response); err != nil {
			logger.Error("Failed to decode rportfwd response: %v", err)
			return
		}

		if response.Success {
			logger.Info("Remote port forward %s: %s", response.Type, response.GUID)
		} else {
			logger.Error("Remote port forward %s failed for %s: %s", response.Type, response.GUID, response.Error)
		}
	})

	// Set up handler for new rportfwd:$GUID channels
	m.peerConn.GetPeerConnection().OnDataChannel(func(dc *pion.DataChannel) {
		if len(dc.Label()) > 9 && dc.Label()[:9] == "rportfwd:" {
			guid := dc.Label()[9:]
			logger.Info("New rportfwd connection channel for GUID: %s", guid)

			m.mu.RLock()
			forward, exists := m.guidToForward[guid]
			m.mu.RUnlock()

			if !exists {
				logger.Error("Received connection for unknown GUID: %s", guid)
				dc.Close()
				return
			}

			// Create a new connection to the target
			conn, err := net.Dial("tcp", forward.Target)
			if err != nil {
				logger.Error("Failed to connect to target %s for GUID %s: %v", forward.Target, guid, err)
				dc.Close()
				return
			}

			// Set up the data channel handlers
			dc.OnOpen(func() {
				logger.Debug("rportfwd connection channel opened for GUID: %s", guid)
			})

			dc.OnClose(func() {
				logger.Debug("rportfwd connection channel closed for GUID: %s", guid)
				conn.Close()
			})

			dc.OnMessage(func(msg pion.DataChannelMessage) {
				logger.Debug("Received %d bytes on rportfwd connection channel for GUID: %s", len(msg.Data), guid)
				if _, err := conn.Write(msg.Data); err != nil {
					logger.Error("Error writing to target connection for GUID %s: %v", guid, err)
					dc.Close()
					return
				}
			})

			// Start the forwarding loop
			go func() {
				buffer := make([]byte, 16384)
				logger.Debug("Starting forward loop for GUID: %s", guid)

				for {
					n, err := conn.Read(buffer)
					if err != nil {
						if err == io.EOF {
							logger.Debug("End of file reached for GUID: %s", guid)
						} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
							continue
						} else {
							logger.Error("Error reading from connection for GUID %s: %v", guid, err)
						}
						dc.Close()
						return
					}

					logger.Debug("Read %d bytes from remote connection for GUID: %s", n, guid)
					if err := dc.Send(buffer[:n]); err != nil {
						logger.Error("Error sending to data channel for GUID %s: %v", guid, err)
						conn.Close()
						return
					}
				}
			}()
		}
	})

	m.started = true
	return nil
}

// StartForward sends a request to start a remote port forward
func (m *RemotePortForwardManager) StartForward(port uint16, targetAddr string) error {
	if !m.started {
		return fmt.Errorf("remote port forward manager not started")
	}

	// Generate a new GUID for this forward
	guid := uuid.New().String()

	// Create the forward mapping
	forward := &PortForward{
		GUID:   guid,
		Port:   fmt.Sprintf("%d", port),
		Target: targetAddr,
	}

	m.mu.Lock()
	m.guidToForward[guid] = forward
	m.portToForward[port] = forward
	m.mu.Unlock()

	// Send the start request
	req := RemotePortForwardRequest{
		Type: "start_rportfwd",
		GUID: guid,
		Port: fmt.Sprintf("%d", port),
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to encode start request: %v", err)
	}

	if err := m.channel.Send(reqBytes); err != nil {
		return fmt.Errorf("failed to send start request: %v", err)
	}

	return nil
}

// StopForward sends a request to stop a remote port forward
func (m *RemotePortForwardManager) StopForward(port uint16) error {
	if !m.started {
		return fmt.Errorf("remote port forward manager not started")
	}

	m.mu.RLock()
	forward, exists := m.portToForward[port]
	if !exists {
		m.mu.RUnlock()
		return fmt.Errorf("no forward found for port %d", port)
	}
	m.mu.RUnlock()

	// Send the stop request
	req := RemotePortForwardRequest{
		Type: "stop_rportfwd",
		GUID: forward.GUID,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to encode stop request: %v", err)
	}

	if err := m.channel.Send(reqBytes); err != nil {
		return fmt.Errorf("failed to send stop request: %v", err)
	}

	// Remove the forward mappings
	m.mu.Lock()
	delete(m.guidToForward, forward.GUID)
	delete(m.portToForward, port)
	m.mu.Unlock()

	return nil
}

// GetForward returns the target address for a given port
func (m *RemotePortForwardManager) GetForward(port uint16) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, forward := range m.guidToForward {
		if forward.Port == fmt.Sprintf("%d", port) {
			return forward.Target, nil
		}
	}

	return "", fmt.Errorf("no forward found for port %d", port)
}

// ListForwards returns a list of all active remote port forwards
func (m *RemotePortForwardManager) ListForwards() []*PortForward {
	m.mu.RLock()
	defer m.mu.RUnlock()

	forwards := make([]*PortForward, 0, len(m.portToForward))
	for _, forward := range m.portToForward {
		forwards = append(forwards, forward)
	}
	return forwards
}

// Close closes the remote port forward manager
func (m *RemotePortForwardManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Close the rportfwd channel if it exists
	if m.channel != nil {
		logger.Info("Closing rportfwd channel")
		if err := m.channel.Close(); err != nil {
			logger.Error("Failed to close rportfwd channel: %v", err)
		}
		m.channel = nil
	}

	// Reset all mappings
	m.portToForward = make(map[uint16]*PortForward)
	m.guidToForward = make(map[string]*PortForward)

	return nil
}
