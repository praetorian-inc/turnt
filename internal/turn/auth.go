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
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"fmt"
)

// ComputeLongTermKey computes MD5(username:realm:password) per RFC 5389 Section 15.4.
func ComputeLongTermKey(username, realm, password string) []byte {
	h := md5.New()
	fmt.Fprintf(h, "%s:%s:%s", username, realm, password)
	return h.Sum(nil)
}

// ComputeMessageIntegrity computes HMAC-SHA1(key, message) per RFC 5389 Section 15.4.
// The message bytes should include the STUN header with the message-length adjusted
// to account for the MESSAGE-INTEGRITY attribute (24 bytes: 4 header + 20 HMAC).
func ComputeMessageIntegrity(key []byte, message []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// ValidateMessageIntegrity checks whether a response contains a valid MESSAGE-INTEGRITY
// for the given key. Returns true if the HMAC matches.
func ValidateMessageIntegrity(responseRaw []byte, key []byte) bool {
	// MESSAGE-INTEGRITY is a 24-byte attribute: 4 bytes header + 20 bytes HMAC-SHA1
	// It must be the last attribute (or second-to-last before FINGERPRINT).
	// Find MESSAGE-INTEGRITY attribute (type 0x0008) in the response.
	if len(responseRaw) < 24 {
		return false
	}

	// Walk attributes to find MESSAGE-INTEGRITY
	offset := 20 // Skip STUN header (20 bytes)
	for offset+4 <= len(responseRaw) {
		attrType := uint16(responseRaw[offset])<<8 | uint16(responseRaw[offset+1])
		attrLen := int(uint16(responseRaw[offset+2])<<8 | uint16(responseRaw[offset+3]))

		if attrType == 0x0008 { // MESSAGE-INTEGRITY
			if attrLen != 20 || offset+4+20 > len(responseRaw) {
				return false
			}
			receivedMAC := responseRaw[offset+4 : offset+4+20]

			// Compute expected HMAC over everything before this attribute,
			// with the message length in the header adjusted to include only
			// up to and including this attribute.
			msgForMAC := make([]byte, offset)
			copy(msgForMAC, responseRaw[:offset])
			// Adjust length field in STUN header: offset - 20 (header) + 24 (this attr)
			adjustedLen := uint16(offset - 20 + 24)
			msgForMAC[2] = byte(adjustedLen >> 8)
			msgForMAC[3] = byte(adjustedLen)

			expectedMAC := ComputeMessageIntegrity(key, msgForMAC)
			return hmac.Equal(receivedMAC, expectedMAC)
		}

		// Advance to next attribute (4-byte aligned)
		padded := attrLen
		if padded%4 != 0 {
			padded += 4 - (padded % 4)
		}
		offset += 4 + padded
	}

	return false
}
