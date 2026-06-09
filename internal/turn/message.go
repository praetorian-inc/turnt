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
	"encoding/binary"
	"fmt"
	"net"

	"github.com/pion/stun"
)

// STUN/TURN message types used in audit operations.
var (
	AllocateRequest         = stun.NewType(stun.MethodAllocate, stun.ClassRequest)
	RefreshRequest          = stun.NewType(stun.MethodRefresh, stun.ClassRequest)
	CreatePermissionRequest = stun.NewType(stun.MethodCreatePermission, stun.ClassRequest)
	ChannelBindRequest      = stun.NewType(stun.MethodChannelBind, stun.ClassRequest)
	SendIndication          = stun.NewType(stun.MethodSend, stun.ClassIndication)
)

// Transport protocol numbers for REQUESTED-TRANSPORT attribute.
const (
	TransportUDP byte = 17
	TransportTCP byte = 6
)

// RequestedTransport implements the REQUESTED-TRANSPORT attribute (0x0019).
type RequestedTransport struct {
	Protocol byte
}

// AddTo adds REQUESTED-TRANSPORT to a STUN message.
func (r RequestedTransport) AddTo(m *stun.Message) error {
	buf := make([]byte, 4)
	buf[0] = r.Protocol
	// bytes 1-3 are RFFU (reserved)
	m.Add(stun.AttrRequestedTransport, buf)
	return nil
}

// Lifetime implements the LIFETIME attribute (0x000D).
type Lifetime struct {
	Duration uint32 // seconds
}

// AddTo adds LIFETIME to a STUN message.
func (l Lifetime) AddTo(m *stun.Message) error {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, l.Duration)
	m.Add(stun.AttrLifetime, buf)
	return nil
}

// GetLifetimeFromMessage extracts the LIFETIME value from a response message.
func GetLifetimeFromMessage(m *stun.Message) (uint32, error) {
	val, err := m.Get(stun.AttrLifetime)
	if err != nil {
		return 0, err
	}
	if len(val) < 4 {
		return 0, fmt.Errorf("lifetime attribute too short: %d bytes", len(val))
	}
	return binary.BigEndian.Uint32(val[:4]), nil
}

// BuildBindingRequest creates a STUN Binding Request message.
func BuildBindingRequest() (*stun.Message, error) {
	return stun.Build(stun.TransactionID, stun.BindingRequest)
}

// BuildAllocateRequest creates an unauthenticated TURN Allocate Request.
// The transport parameter specifies UDP (17) or TCP (6) for the relay.
func BuildAllocateRequest(transport byte) (*stun.Message, error) {
	return stun.Build(
		stun.TransactionID,
		AllocateRequest,
		RequestedTransport{Protocol: transport},
	)
}

// BuildAuthenticatedAllocate creates a TURN Allocate Request with authentication.
func BuildAuthenticatedAllocate(transport byte, username, realm, nonce string, key []byte) (*stun.Message, error) {
	msg, err := stun.Build(
		stun.TransactionID,
		AllocateRequest,
		RequestedTransport{Protocol: transport},
		stun.NewUsername(username),
		stun.NewRealm(realm),
		stun.NewNonce(nonce),
		stun.MessageIntegrity(key),
	)
	if err != nil {
		return nil, fmt.Errorf("build authenticated allocate: %w", err)
	}
	return msg, nil
}

// BuildCreatePermission creates a CreatePermission Request with authentication.
// The peerAddr is the IP that the relay should permit traffic to.
func BuildCreatePermission(peerAddr net.IP, peerPort int, username, realm, nonce string, key []byte) (*stun.Message, error) {
	msg := stun.New()
	msg.SetType(CreatePermissionRequest)
	if err := msg.NewTransactionID(); err != nil {
		return nil, err
	}

	// Add XOR-PEER-ADDRESS using our custom encoder for IPv6 support
	xorAttr := XORPeerAddress(peerAddr, peerPort, msg.TransactionID)
	msg.Add(xorAttr.Type, xorAttr.Value)

	// Add auth attributes
	stun.NewUsername(username).AddTo(msg)
	stun.NewRealm(realm).AddTo(msg)
	stun.NewNonce(nonce).AddTo(msg)

	// Add MESSAGE-INTEGRITY (must be last, or second-to-last before FINGERPRINT)
	stun.MessageIntegrity(key).AddTo(msg)

	return msg, nil
}

// BuildRefresh creates a Refresh Request with the given lifetime.
// lifetime=0 deallocates the relay address.
func BuildRefresh(lifetime uint32, username, realm, nonce string, key []byte) (*stun.Message, error) {
	msg, err := stun.Build(
		stun.TransactionID,
		RefreshRequest,
		Lifetime{Duration: lifetime},
		stun.NewUsername(username),
		stun.NewRealm(realm),
		stun.NewNonce(nonce),
		stun.MessageIntegrity(key),
	)
	if err != nil {
		return nil, fmt.Errorf("build refresh: %w", err)
	}
	return msg, nil
}

// ParseErrorCode extracts the error code and reason from a STUN error response.
func ParseErrorCode(m *stun.Message) (int, string, error) {
	var errCode stun.ErrorCodeAttribute
	if err := errCode.GetFrom(m); err != nil {
		return 0, "", err
	}
	return int(errCode.Code), string(errCode.Reason), nil
}

// ParseSoftware extracts the SOFTWARE attribute from a STUN message.
func ParseSoftware(m *stun.Message) string {
	var sw stun.Software
	if err := sw.GetFrom(m); err != nil {
		return ""
	}
	return string(sw)
}

// ParseRealm extracts the REALM attribute from a STUN message.
func ParseRealm(m *stun.Message) string {
	var r stun.Realm
	if err := r.GetFrom(m); err != nil {
		return ""
	}
	return string(r)
}

// ParseNonce extracts the NONCE attribute from a STUN message.
func ParseNonce(m *stun.Message) string {
	var n stun.Nonce
	if err := n.GetFrom(m); err != nil {
		return ""
	}
	return string(n)
}
