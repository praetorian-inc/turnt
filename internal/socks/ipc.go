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

type connectionDetails struct {
	NetworkType string `json:"network_type"`
	TargetAddr  string `json:"target_addr"`
}

// RemotePortForwardRequest represents a request to start or stop a remote port forward
type RemotePortForwardRequest struct {
	Type string `json:"type"`
	GUID string `json:"guid"`
	Port string `json:"port"` // The port to bind to on the relay (e.g. "8080")
}

// RemotePortForwardResponse represents a response to a remote port forward request
type RemotePortForwardResponse struct {
	Type    string `json:"type"`
	GUID    string `json:"guid"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}
