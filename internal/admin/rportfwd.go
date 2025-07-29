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
	"strconv"
	"strings"

	"github.com/praetorian-inc/turnt/internal/logger"
	"github.com/praetorian-inc/turnt/internal/socks"
)

// RemotePortForwardRequest represents a request to start or stop a remote port forward
type RemotePortForwardRequest struct {
	Port   uint16 `json:"port"`
	Target string `json:"target"`
}

// RemotePortForwardResponse represents a response from a remote port forward request
type RemotePortForwardResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// RemotePortForward represents an active remote port forward
type RemotePortForward struct {
	Port   uint16 `json:"port"`
	Target string `json:"target"`
}

// RemotePortForwardList represents a list of active remote port forwards
type RemotePortForwardList struct {
	Forwards []RemotePortForward `json:"forwards"`
}

// Forward represents a remote port forward entry
type Forward struct {
	Port   uint16
	Target string
}

// HandleRemotePortForward handles remote port forward commands
func (s *Server) HandleRemotePortForward(cmd Command) Response {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.socksServer == nil {
		return Response{
			Success: false,
			Message: "SOCKS server not initialized",
		}
	}

	rportfwd := s.socksServer.GetRemotePortForwardManager()
	if rportfwd == nil {
		return Response{
			Success: false,
			Message: "Remote port forward manager not initialized",
		}
	}

	switch cmd.Type {
	case "list_rportfwd":
		socksForwards := rportfwd.ListForwards()
		forwards := make([]socks.PortForward, len(socksForwards))
		for i, f := range socksForwards {
			forwards[i] = *f // Dereference the pointer
		}

		if len(forwards) == 0 {
			return Response{
				Success: true,
				Message: "No active remote port forwards",
			}
		}

		var sb strings.Builder
		sb.WriteString("Active remote port forwards:\n")
		for _, f := range forwards {
			sb.WriteString(fmt.Sprintf("  %s -> %s\n", f.Port, f.Target))
		}

		return Response{
			Success: true,
			Message: sb.String(),
		}

	case "start_rportfwd":
		port, ok := cmd.Payload["port"].(uint16)
		if !ok {
			return Response{
				Success: false,
				Message: "Port is required",
			}
		}

		target, ok := cmd.Payload["target"].(string)
		if !ok || target == "" {
			return Response{
				Success: false,
				Message: "Target is required",
			}
		}

		if err := rportfwd.StartForward(port, target); err != nil {
			logger.Error("Failed to start remote port forward: %v", err)
			return Response{
				Success: false,
				Message: fmt.Sprintf("Failed to start remote port forward: %v", err),
			}
		}

		return Response{
			Success: true,
		}

	case "stop_rportfwd":
		portStr, ok := cmd.Payload["port"].(string)
		if !ok || portStr == "" {
			return Response{
				Success: false,
				Message: "Port is required",
			}
		}

		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return Response{
				Success: false,
				Message: "Invalid port",
			}
		}

		if err := rportfwd.StopForward(uint16(port)); err != nil {
			logger.Error("Failed to stop remote port forward: %v", err)
			return Response{
				Success: false,
				Message: fmt.Sprintf("Failed to stop remote port forward: %v", err),
			}
		}

		return Response{
			Success: true,
		}

	default:
		return Response{
			Success: false,
			Message: fmt.Sprintf("Unknown command type: %s", cmd.Type),
		}
	}
}
