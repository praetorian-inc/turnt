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
	"encoding/hex"
	"fmt"

	"github.com/pion/stun"
	"github.com/praetorian-inc/turnt/internal/turn"
)

// MemoryLeakConfig configures the memory disclosure test.
type MemoryLeakConfig struct {
	ServerAddr string
	Protocol   string
	Username   string
	Password   string
	AttrType   uint16 // attribute type for malformed TLV (default 0x0006 USERNAME)
	Overflow   int    // extra bytes to claim beyond actual data
	Count      int    // number of probes to send
}

// MemoryLeakResult contains the results of a memory disclosure probe.
type MemoryLeakResult struct {
	ProbesSent      int
	ResponsesRecvd  int
	BaselineSize    int    // normal response size for a valid Binding Request
	MaxResponseSize int    // largest response from malformed probes
	ExtraBytes      int    // max extra bytes beyond baseline
	LeakDetected    bool
	SampleHex       string // hex dump of extra data from the largest response
}

// TestMemoryLeak sends STUN messages with TLV length exceeding actual data
// and analyzes responses for leaked heap memory.
func TestMemoryLeak(cfg MemoryLeakConfig) (*MemoryLeakResult, error) {
	if cfg.AttrType == 0 {
		cfg.AttrType = 0x0006 // USERNAME
	}
	if cfg.Overflow <= 0 {
		cfg.Overflow = 256
	}
	if cfg.Count <= 0 {
		cfg.Count = 10
	}

	client, err := turn.NewClient(turn.ClientConfig{
		ServerAddr: cfg.ServerAddr,
		Protocol:   cfg.Protocol,
		Username:   cfg.Username,
		Password:   cfg.Password,
	})
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer client.Close()

	result := &MemoryLeakResult{}

	// Get baseline: send a normal Binding Request and measure response size
	_, baselineRaw, err := client.SendBindingRequest()
	if err != nil {
		return nil, fmt.Errorf("baseline binding request: %w", err)
	}
	result.BaselineSize = len(baselineRaw)

	// Send malformed probes
	for i := 0; i < cfg.Count; i++ {
		result.ProbesSent++

		// Build a malformed STUN Binding Request with oversized TLV
		actualData := []byte("test") // 4 bytes of real data
		claimedLength := uint16(len(actualData) + cfg.Overflow)
		malformed := turn.BuildMalformedSTUNMessage(
			stun.BindingRequest,
			cfg.AttrType,
			actualData,
			claimedLength,
		)

		respRaw, respLen, err := client.SendRawBytes(malformed)
		if err != nil {
			continue
		}
		result.ResponsesRecvd++

		if respLen > result.MaxResponseSize {
			result.MaxResponseSize = respLen

			// Check for extra data beyond baseline
			extra := respLen - result.BaselineSize
			if extra > result.ExtraBytes {
				result.ExtraBytes = extra
				// Save hex sample of the extra bytes
				if extra > 0 && respLen > result.BaselineSize {
					start := result.BaselineSize
					end := respLen
					if end-start > 512 { // cap hex dump
						end = start + 512
					}
					result.SampleHex = hex.Dump(respRaw[start:end])
				}
			}
		}
	}

	// Heuristic: if responses are consistently larger than baseline, potential leak
	if result.ExtraBytes > 16 {
		result.LeakDetected = true
	}

	return result, nil
}
