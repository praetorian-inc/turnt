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

package admin

import (
	"fmt"
	"net"
	"strings"

	"github.com/praetorian-inc/turnt/internal/lportfwd"
)

// LocalPortForward represents a local port forward
type LocalPortForward struct {
	LHost string
	LPort string
	RHost string
	RPort string
}

// PortForwardManager manages local port forwards
type PortForwardManager struct {
	server *lportfwd.Server
}

// NewPortForwardManager creates a new port forward manager
func NewPortForwardManager(socksAddr string) *PortForwardManager {
	return &PortForwardManager{
		server: lportfwd.NewServer(socksAddr),
	}
}

// HandleAdd handles the lportfwd add command
func (m *PortForwardManager) HandleAdd(cmd Command) Response {
	if len(cmd.Args) != 2 {
		return Response{
			Success: false,
			Message: "usage: lportfwd add <local_port> <remote_ip>:<remote_port>",
		}
	}

	// Parse local port
	lport := cmd.Args[0]
	if _, err := net.LookupPort("tcp", lport); err != nil {
		return Response{
			Success: false,
			Message: fmt.Sprintf("invalid local port: %v", err),
		}
	}

	// Parse remote address
	rhost, rport := splitHostPort(cmd.Args[1])
	if rhost == "" || rport == "" {
		return Response{
			Success: false,
			Message: "invalid remote address format - must be IP:PORT (e.g. 96.7.128.175:80). Hostnames/FQDNs are not supported.",
		}
	}

	// Use 0.0.0.0 to bind to all interfaces
	if err := m.server.AddForward("0.0.0.0", lport, rhost, rport); err != nil {
		return Response{
			Success: false,
			Message: fmt.Sprintf("Failed to add port forward: %v", err),
		}
	}

	return Response{
		Success: true,
		Message: fmt.Sprintf("Added port forward from *:%s to %s:%s", lport, rhost, rport),
	}
}

func splitHostPort(s string) (string, string) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", ""
	}

	// Validate that host is an IP address
	ip := net.ParseIP(host)
	if ip == nil {
		return "", ""
	}

	// Validate port is a valid TCP port
	if _, err := net.LookupPort("tcp", port); err != nil {
		return "", ""
	}

	return host, port
}

// HandleRemove handles the lportfwd remove command
func (m *PortForwardManager) HandleRemove(cmd Command) Response {
	if len(cmd.Args) != 1 {
		return Response{
			Success: false,
			Message: "usage: lportfwd remove <local_port>",
		}
	}

	port := cmd.Args[0]
	if err := m.server.RemoveForward(port); err != nil {
		return Response{
			Success: false,
			Message: fmt.Sprintf("Failed to remove port forward: %v", err),
		}
	}

	return Response{
		Success: true,
		Message: fmt.Sprintf("Removed port forward on local port %s", port),
	}
}

// HandleList handles the lportfwd list command
func (m *PortForwardManager) HandleList(cmd Command) Response {
	forwards := m.server.ListForwards()
	if len(forwards) == 0 {
		return Response{
			Success: true,
			Message: "No active port forwards",
		}
	}

	var sb strings.Builder
	sb.WriteString("Active port forwards:\n")
	for _, f := range forwards {
		// Only show the port number for local address
		sb.WriteString(fmt.Sprintf("  %s -> %s:%s\n", f.LPort, f.RHost, f.RPort))
	}

	return Response{
		Success: true,
		Message: sb.String(),
	}
}
