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

	"github.com/pion/stun"
	"github.com/praetorian-inc/turnt/internal/turn"
)

// AuthResult contains the results of authentication testing.
type AuthResult struct {
	AnonymousAccess bool   // true if server accepts unauthenticated Allocate
	CredentialValid bool   // true if provided credentials work
	Realm           string // REALM from 401 response
	Nonce           string // NONCE from 401 response
	ErrorCode       int    // Error code from credential test
	ErrorReason     string // Error reason from credential test
}

// TestAnonymousAccess checks whether the TURN server allows unauthenticated allocations.
func TestAnonymousAccess(serverAddr, protocol string) (*AuthResult, error) {
	result := &AuthResult{}

	client, err := turn.NewClient(turn.ClientConfig{
		ServerAddr: serverAddr,
		Protocol:   protocol,
	})
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer client.Close()

	resp, err := client.SendAllocateRequest()
	if err != nil {
		return nil, fmt.Errorf("send allocate: %w", err)
	}

	if resp.Type.Class == stun.ClassSuccessResponse {
		result.AnonymousAccess = true
		return result, nil
	}

	if resp.Type.Class == stun.ClassErrorResponse {
		code, reason, _ := turn.ParseErrorCode(resp)
		result.ErrorCode = code
		result.ErrorReason = reason
		result.Realm = turn.ParseRealm(resp)
		result.Nonce = turn.ParseNonce(resp)
	}

	return result, nil
}

// TestCredentials validates whether the given credentials can create an allocation.
func TestCredentials(serverAddr, protocol, username, password string) (*AuthResult, error) {
	result := &AuthResult{}

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

	// Learn auth params (realm, nonce) from 401
	err = client.LearnAuthParams()
	if err != nil {
		// If error contains "no-auth", server doesn't require auth
		result.AnonymousAccess = client.IsNoAuth()
		if result.AnonymousAccess {
			return result, nil
		}
		return nil, fmt.Errorf("learn auth params: %w", err)
	}

	result.Realm = client.GetRealm()
	result.Nonce = client.GetNonce()

	// Now try authenticated allocate
	resp, err := client.SendAuthenticatedAllocate()
	if err != nil {
		return nil, fmt.Errorf("authenticated allocate: %w", err)
	}

	if resp.Type.Class == stun.ClassSuccessResponse {
		result.CredentialValid = true
		// Clean up: deallocate
		client.SendRefresh(0)
		return result, nil
	}

	if resp.Type.Class == stun.ClassErrorResponse {
		code, reason, _ := turn.ParseErrorCode(resp)
		result.ErrorCode = code
		result.ErrorReason = reason
	}

	return result, nil
}
