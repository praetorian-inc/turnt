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

// DefaultScanTargets returns the standard set of addresses to probe.
var DefaultScanTargets = []struct {
	IP    string
	Label string
}{
	{"10.0.0.1", "RFC1918 (10.x)"},
	{"172.16.0.1", "RFC1918 (172.16.x)"},
	{"192.168.0.1", "RFC1918 (192.168.0.x)"},
	{"192.168.1.1", "RFC1918 (192.168.1.x)"},
	{"127.0.0.1", "Loopback"},
	{"169.254.169.254", "Cloud metadata"},
	{"169.254.0.1", "Link-local"},
	{"8.8.8.8", "Public internet"},
}

// ScanRelayScope tests which peer addresses the TURN relay permits.
// Requires valid credentials. Allocates first, then sends CreatePermission
// for each target and reports ALLOWED/DENIED.
func ScanRelayScope(serverAddr, protocol, username, password string, targets []struct {
	IP    string
	Label string
}, port int) ([]ScanResult, error) {
	client, err := turn.NewClient(turn.ClientConfig{
		ServerAddr: serverAddr,
		Protocol:   protocol,
		Username:   username,
		Password:   password,
	})
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer client.Close()

	// Learn auth params
	if err := client.LearnAuthParams(); err != nil {
		return nil, fmt.Errorf("learn auth: %w", err)
	}

	// Allocate
	allocResp, err := client.SendAuthenticatedAllocate()
	if err != nil {
		return nil, fmt.Errorf("allocate: %w", err)
	}
	if allocResp.Type.Class != stun.ClassSuccessResponse {
		code, reason, _ := turn.ParseErrorCode(allocResp)
		return nil, fmt.Errorf("allocate failed: %d %s", code, reason)
	}

	// Probe each target
	results := make([]ScanResult, 0, len(targets))
	for _, target := range targets {
		ip := net.ParseIP(target.IP)
		if ip == nil {
			results = append(results, ScanResult{
				Address: target.IP,
				Label:   target.Label,
				Allowed: false,
				Error:   "invalid IP",
			})
			continue
		}

		resp, err := client.SendCreatePermission(ip, port)
		if err != nil {
			results = append(results, ScanResult{
				Address: target.IP,
				Label:   target.Label,
				Allowed: false,
				Error:   err.Error(),
			})
			continue
		}

		result := ScanResult{
			Address: target.IP,
			Label:   target.Label,
		}

		if resp.Type.Class == stun.ClassSuccessResponse {
			result.Allowed = true
		} else if resp.Type.Class == stun.ClassErrorResponse {
			code, reason, _ := turn.ParseErrorCode(resp)
			result.Allowed = false
			result.ErrCode = code
			result.Error = fmt.Sprintf("%d %s", code, reason)
		}

		results = append(results, result)
	}

	// Deallocate
	client.SendRefresh(0)

	return results, nil
}
