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
	"time"

	"github.com/pion/stun"
	"github.com/praetorian-inc/turnt/internal/turn"
)

// FloodConfig configures the allocation flood test.
type FloodConfig struct {
	ServerAddr string
	Protocol   string
	Username   string
	Password   string
	MaxAllocs  int
	Delay      time.Duration
}

// FloodResult contains the results of an allocation flood test.
type FloodResult struct {
	Allocations int
	QuotaHit    bool  // true if server returned 486 (Allocation Quota Reached)
	LastError   int   // last error code received
	LastReason  string
	Duration    time.Duration
}

// TestAllocationFlood creates allocations until the server refuses or max is reached.
// Each allocation uses a separate client/transport to get a distinct relay address.
func TestAllocationFlood(cfg FloodConfig) (*FloodResult, error) {
	if cfg.MaxAllocs <= 0 {
		cfg.MaxAllocs = 1000
	}

	result := &FloodResult{}
	startTime := time.Now()

	// Keep track of clients so we can clean up
	var clients []*turn.Client

	defer func() {
		// Deallocate all
		for _, c := range clients {
			c.SendRefresh(0)
			c.Close()
		}
	}()

	for i := 0; i < cfg.MaxAllocs; i++ {
		client, err := turn.NewClient(turn.ClientConfig{
			ServerAddr: cfg.ServerAddr,
			Protocol:   cfg.Protocol,
			Username:   cfg.Username,
			Password:   cfg.Password,
		})
		if err != nil {
			result.Duration = time.Since(startTime)
			result.LastReason = fmt.Sprintf("connection error: %v", err)
			return result, nil
		}

		// Learn auth params
		if err := client.LearnAuthParams(); err != nil {
			client.Close()
			result.Duration = time.Since(startTime)
			result.LastReason = fmt.Sprintf("auth error: %v", err)
			return result, nil
		}

		// Try to allocate
		resp, err := client.SendAuthenticatedAllocate()
		if err != nil {
			client.Close()
			result.Duration = time.Since(startTime)
			result.LastReason = fmt.Sprintf("allocate send error: %v", err)
			return result, nil
		}

		if resp.Type.Class == stun.ClassSuccessResponse {
			result.Allocations++
			clients = append(clients, client)
		} else if resp.Type.Class == stun.ClassErrorResponse {
			code, reason, _ := turn.ParseErrorCode(resp)
			result.LastError = code
			result.LastReason = reason
			client.Close()

			if code == 486 {
				result.QuotaHit = true
				break
			}
			// Other errors (e.g., 508 Insufficient Capacity)
			break
		}

		if cfg.Delay > 0 {
			time.Sleep(cfg.Delay)
		}

		// Print progress every 100 allocations
		if (i+1)%100 == 0 {
			fmt.Printf("[i] Created %d allocations...\n", result.Allocations)
		}
	}

	result.Duration = time.Since(startTime)
	return result, nil
}
