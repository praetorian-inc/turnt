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

package turn

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/stun"
)

// Client is a raw STUN/TURN protocol client for adversarial testing.
// It provides direct control over message construction, supports
// unauthenticated requests, and enables precise response measurement.
type Client struct {
	transport Transport
	realm     string
	nonce     string
	username  string
	password  string
	key       []byte // MD5(username:realm:password)
	timeout   time.Duration
	mu        sync.Mutex
}

// ClientConfig holds parameters for creating a Client.
type ClientConfig struct {
	ServerAddr string
	Protocol   string // "udp", "tcp", "tls"
	Username   string
	Password   string
	Timeout    time.Duration
}

// NewClient creates a Client with a transport to the specified server.
func NewClient(cfg ClientConfig) (*Client, error) {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	transport, err := NewTransport(TransportConfig{
		ServerAddr: cfg.ServerAddr,
		Protocol:   cfg.Protocol,
		Timeout:    timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("create transport: %w", err)
	}

	return &Client{
		transport: transport,
		username:  cfg.Username,
		password:  cfg.Password,
		timeout:   timeout,
	}, nil
}

// NewClientWithTransport creates a Client using an existing transport.
func NewClientWithTransport(transport Transport, username, password string, timeout time.Duration) *Client {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	return &Client{
		transport: transport,
		username:  username,
		password:  password,
		timeout:   timeout,
	}
}

// sendAndReceive sends a STUN message and reads the response.
// Returns the parsed response message and the raw response bytes.
func (c *Client) sendAndReceive(msg *stun.Message) (*stun.Message, []byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.transport.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return nil, nil, fmt.Errorf("set deadline: %w", err)
	}

	raw := msg.Raw
	if _, err := c.transport.Send(raw); err != nil {
		return nil, nil, fmt.Errorf("send: %w", err)
	}

	buf := make([]byte, 65535)
	n, err := c.transport.Recv(buf)
	if err != nil {
		return nil, nil, fmt.Errorf("recv: %w", err)
	}

	responseRaw := make([]byte, n)
	copy(responseRaw, buf[:n])

	resp := stun.New()
	resp.Raw = responseRaw
	if err := resp.Decode(); err != nil {
		return nil, responseRaw, fmt.Errorf("decode response: %w", err)
	}

	return resp, responseRaw, nil
}

// SendBindingRequest sends a STUN Binding Request and returns the response.
// Used for fingerprinting (SOFTWARE attribute) and amplification testing.
func (c *Client) SendBindingRequest() (*stun.Message, []byte, error) {
	msg, err := BuildBindingRequest()
	if err != nil {
		return nil, nil, err
	}
	return c.sendAndReceive(msg)
}

// SendAllocateRequest sends an unauthenticated TURN Allocate Request.
// A 401 response is expected (server requires auth). Success means no-auth mode.
func (c *Client) SendAllocateRequest() (*stun.Message, error) {
	msg, err := BuildAllocateRequest(TransportUDP)
	if err != nil {
		return nil, err
	}
	resp, _, err := c.sendAndReceive(msg)
	return resp, err
}

// SendAuthenticatedAllocate sends a TURN Allocate with MESSAGE-INTEGRITY.
// Uses realm/nonce learned from a prior 401 response.
func (c *Client) SendAuthenticatedAllocate() (*stun.Message, error) {
	if c.realm == "" || c.nonce == "" {
		return nil, fmt.Errorf("realm and nonce not learned; call LearnAuthParams first")
	}
	if c.key == nil {
		c.key = ComputeLongTermKey(c.username, c.realm, c.password)
	}

	msg, err := BuildAuthenticatedAllocate(TransportUDP, c.username, c.realm, c.nonce, c.key)
	if err != nil {
		return nil, err
	}
	resp, _, err := c.sendAndReceive(msg)
	return resp, err
}

// SendCreatePermission sends CreatePermission for the given peer address.
// Requires a prior successful allocation. Returns the response message.
func (c *Client) SendCreatePermission(peerAddr net.IP, peerPort int) (*stun.Message, error) {
	if c.realm == "" || c.nonce == "" {
		return nil, fmt.Errorf("realm and nonce not learned; call LearnAuthParams first")
	}
	if c.key == nil {
		c.key = ComputeLongTermKey(c.username, c.realm, c.password)
	}

	msg, err := BuildCreatePermission(peerAddr, peerPort, c.username, c.realm, c.nonce, c.key)
	if err != nil {
		return nil, err
	}
	resp, _, err := c.sendAndReceive(msg)
	return resp, err
}

// SendCreatePermissionIPv6Explicit sends CreatePermission using explicit IPv6 encoding
// for ACL bypass testing. Converts an IPv4 address to ::ffff:x.x.x.x format.
func (c *Client) SendCreatePermissionIPv6Explicit(ipv4 net.IP, peerPort int) (*stun.Message, error) {
	if c.realm == "" || c.nonce == "" {
		return nil, fmt.Errorf("realm and nonce not learned; call LearnAuthParams first")
	}
	if c.key == nil {
		c.key = ComputeLongTermKey(c.username, c.realm, c.password)
	}

	msg := stun.New()
	msg.SetType(CreatePermissionRequest)
	if err := msg.NewTransactionID(); err != nil {
		return nil, err
	}

	xorAttr := XORPeerAddressIPv6Explicit(ipv4, peerPort, msg.TransactionID)
	msg.Add(xorAttr.Type, xorAttr.Value)

	stun.NewUsername(c.username).AddTo(msg)
	stun.NewRealm(c.realm).AddTo(msg)
	stun.NewNonce(c.nonce).AddTo(msg)
	stun.MessageIntegrity(c.key).AddTo(msg)

	resp, _, err := c.sendAndReceive(msg)
	return resp, err
}

// SendRawBytes sends arbitrary bytes and returns the raw response.
// Used for malformed packet testing (memory leak).
func (c *Client) SendRawBytes(data []byte) ([]byte, int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.transport.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return nil, 0, fmt.Errorf("set deadline: %w", err)
	}

	if _, err := c.transport.Send(data); err != nil {
		return nil, 0, fmt.Errorf("send: %w", err)
	}

	buf := make([]byte, 65535)
	n, err := c.transport.Recv(buf)
	if err != nil {
		return nil, 0, fmt.Errorf("recv: %w", err)
	}

	return buf[:n], n, nil
}

// SendRefresh sends a Refresh request with the given lifetime.
// Use lifetime=0 to deallocate.
func (c *Client) SendRefresh(lifetime uint32) (*stun.Message, error) {
	if c.realm == "" || c.nonce == "" {
		return nil, fmt.Errorf("realm and nonce not learned; call LearnAuthParams first")
	}
	if c.key == nil {
		c.key = ComputeLongTermKey(c.username, c.realm, c.password)
	}

	msg, err := BuildRefresh(lifetime, c.username, c.realm, c.nonce, c.key)
	if err != nil {
		return nil, err
	}
	resp, _, err := c.sendAndReceive(msg)
	return resp, err
}

// LearnAuthParams sends an unauthenticated Allocate to extract REALM and NONCE
// from the 401 response.
func (c *Client) LearnAuthParams() error {
	resp, err := c.SendAllocateRequest()
	if err != nil {
		return fmt.Errorf("send allocate: %w", err)
	}

	// Check if this is a 401 response
	if resp.Type.Class == stun.ClassErrorResponse {
		code, _, _ := ParseErrorCode(resp)
		if code == 401 {
			c.realm = ParseRealm(resp)
			c.nonce = ParseNonce(resp)
			if c.realm == "" {
				return fmt.Errorf("server returned 401 but no REALM attribute")
			}
			if c.nonce == "" {
				return fmt.Errorf("server returned 401 but no NONCE attribute")
			}
			// Compute the key now that we have the realm
			if c.username != "" && c.password != "" {
				c.key = ComputeLongTermKey(c.username, c.realm, c.password)
			}
			return nil
		}
		return fmt.Errorf("unexpected error response: %d", code)
	}

	// If we got a success response, the server has no authentication!
	if resp.Type.Class == stun.ClassSuccessResponse {
		return fmt.Errorf("server accepted unauthenticated Allocate (no-auth mode)")
	}

	return fmt.Errorf("unexpected response type: %s", resp.Type)
}

// IsNoAuth returns true if the server does not require authentication.
// Call this after LearnAuthParams returns an error containing "no-auth".
func (c *Client) IsNoAuth() bool {
	resp, err := c.SendAllocateRequest()
	if err != nil {
		return false
	}
	return resp.Type.Class == stun.ClassSuccessResponse
}

// GetRealm returns the REALM learned from the server.
func (c *Client) GetRealm() string { return c.realm }

// GetNonce returns the NONCE learned from the server.
func (c *Client) GetNonce() string { return c.nonce }

// SetCredentials updates the client credentials and recomputes the key.
func (c *Client) SetCredentials(username, password string) {
	c.username = username
	c.password = password
	if c.realm != "" {
		c.key = ComputeLongTermKey(username, c.realm, password)
	}
}

// UpdateNonce updates the nonce (used after receiving a 438 Stale Nonce response).
func (c *Client) UpdateNonce(nonce string) {
	c.nonce = nonce
}

// SetRealm sets the REALM on the client.
func (c *Client) SetRealm(realm string) {
	c.realm = realm
}

// Close closes the underlying transport.
func (c *Client) Close() error {
	return c.transport.Close()
}
