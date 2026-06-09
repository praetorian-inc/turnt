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

	"github.com/praetorian-inc/turnt/internal/turn"
)

// AmplificationConfig configures the amplification ratio test.
type AmplificationConfig struct {
	ServerAddr string
	Protocol   string
	Count      int // number of requests to send
}

// AmplificationResult contains the amplification measurement.
type AmplificationResult struct {
	RequestsSent     int
	ResponsesRecvd   int
	RequestSize      int     // size of a minimal Binding Request (bytes)
	AvgResponseSize  float64 // average response size (bytes)
	MaxResponseSize  int
	MinResponseSize  int
	AmplificationRatio float64 // avg_response / request
}

// TestAmplification measures the STUN amplification ratio by sending minimal
// Binding Requests and comparing request/response sizes.
func TestAmplification(cfg AmplificationConfig) (*AmplificationResult, error) {
	if cfg.Count <= 0 {
		cfg.Count = 100
	}

	client, err := turn.NewClient(turn.ClientConfig{
		ServerAddr: cfg.ServerAddr,
		Protocol:   cfg.Protocol,
	})
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer client.Close()

	result := &AmplificationResult{
		MinResponseSize: 1<<31 - 1,
	}

	// Build a minimal Binding Request to measure its size
	msg, err := turn.BuildBindingRequest()
	if err != nil {
		return nil, fmt.Errorf("build binding request: %w", err)
	}
	result.RequestSize = len(msg.Raw)

	totalResponseSize := 0

	for i := 0; i < cfg.Count; i++ {
		result.RequestsSent++

		_, responseRaw, err := client.SendBindingRequest()
		if err != nil {
			continue
		}
		result.ResponsesRecvd++

		respSize := len(responseRaw)
		totalResponseSize += respSize

		if respSize > result.MaxResponseSize {
			result.MaxResponseSize = respSize
		}
		if respSize < result.MinResponseSize {
			result.MinResponseSize = respSize
		}
	}

	if result.ResponsesRecvd > 0 {
		result.AvgResponseSize = float64(totalResponseSize) / float64(result.ResponsesRecvd)
		if result.RequestSize > 0 {
			result.AmplificationRatio = result.AvgResponseSize / float64(result.RequestSize)
		}
	}

	if result.MinResponseSize == 1<<31-1 {
		result.MinResponseSize = 0
	}

	return result, nil
}
