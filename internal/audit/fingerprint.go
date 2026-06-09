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

package audit

import (
	"fmt"
	"net"

	"github.com/pion/stun"
	"github.com/praetorian-inc/turnt/internal/turn"
)

// ServerInfo contains fingerprinting information about a TURN server.
type ServerInfo struct {
	Software   string
	Realm      string
	Nonce      string
	Transports []TransportStatus
}

// TransportStatus reports whether a given transport/port is available.
type TransportStatus struct {
	Protocol string
	Port     string
	Open     bool
	Error    string
}

// Fingerprint probes a TURN server and extracts identifying information.
func Fingerprint(serverAddr, protocol string) (*ServerInfo, error) {
	info := &ServerInfo{}

	// Create a client for the primary probe
	client, err := turn.NewClient(turn.ClientConfig{
		ServerAddr: serverAddr,
		Protocol:   protocol,
	})
	if err != nil {
		return nil, fmt.Errorf("connect to server: %w", err)
	}
	defer client.Close()

	// Send STUN Binding Request to extract SOFTWARE attribute
	resp, _, err := client.SendBindingRequest()
	if err != nil {
		return nil, fmt.Errorf("binding request: %w", err)
	}

	info.Software = turn.ParseSoftware(resp)

	// Send unauthenticated Allocate to get REALM and NONCE from 401
	allocResp, err := client.SendAllocateRequest()
	if err == nil && allocResp != nil {
		if allocResp.Type.Class == stun.ClassErrorResponse {
			info.Realm = turn.ParseRealm(allocResp)
			info.Nonce = turn.ParseNonce(allocResp)
		}
	}

	return info, nil
}

// EnumerateTransports probes multiple transport/port combinations.
func EnumerateTransports(host string) []TransportStatus {
	// Extract host without port
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}

	probes := []struct {
		protocol string
		port     string
	}{
		{"udp", "3478"},
		{"tcp", "3478"},
		{"tls", "5349"},
	}

	results := make([]TransportStatus, 0, len(probes))
	for _, p := range probes {
		status := TransportStatus{
			Protocol: p.protocol,
			Port:     p.port,
		}

		addr := net.JoinHostPort(h, p.port)
		client, err := turn.NewClient(turn.ClientConfig{
			ServerAddr: addr,
			Protocol:   p.protocol,
		})
		if err != nil {
			status.Open = false
			status.Error = err.Error()
			results = append(results, status)
			continue
		}

		_, _, err = client.SendBindingRequest()
		client.Close()

		if err != nil {
			status.Open = false
			status.Error = err.Error()
		} else {
			status.Open = true
		}

		results = append(results, status)
	}

	return results
}
