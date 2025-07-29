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

package webrtc

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pion/ice/v2"
	"github.com/pion/webrtc/v3"
	pion "github.com/pion/webrtc/v3"
	"github.com/praetorian-inc/turnt/internal/config"
	"github.com/praetorian-inc/turnt/internal/utils"
)

type WebRTCPeerConnection struct {
	peerConnection *pion.PeerConnection
	Control        *webrtc.DataChannel
	dataChannels   map[string]*webrtc.DataChannel
	mu             sync.RWMutex
}

type OfferPayload struct {
	OfferSDP   string           `json:"offer_sdp"`
	ICEServers []pion.ICEServer `json:"ice_servers"`
}

func NewPeerConnection(iceServers []pion.ICEServer) (*WebRTCPeerConnection, error) {
	settingEngine := pion.SettingEngine{}
	settingEngine.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)

	settingEngine.SetNetworkTypes([]pion.NetworkType{
		pion.NetworkTypeTCP4,
		pion.NetworkTypeTCP6,
	})

	settingEngine.SetICETimeouts(
		30*time.Second,
		5*time.Minute,
		10*time.Second,
	)

	api := pion.NewAPI(pion.WithSettingEngine(settingEngine))

	rtcConfig := pion.Configuration{
		ICEServers:         iceServers,
		ICETransportPolicy: pion.ICETransportPolicyRelay,
	}

	peer, err := api.NewPeerConnection(rtcConfig)
	if err != nil {
		return nil, err
	}

	conn := &WebRTCPeerConnection{
		peerConnection: peer,
		dataChannels:   make(map[string]*webrtc.DataChannel),
	}

	// Set up data channel tracking
	peer.OnDataChannel(func(channel *webrtc.DataChannel) {
		conn.mu.Lock()
		conn.dataChannels[channel.Label()] = channel
		conn.mu.Unlock()
	})

	return conn, nil
}

func (c *WebRTCPeerConnection) CreateDataChannel(label string, options *pion.DataChannelInit) (*pion.DataChannel, error) {
	if c.peerConnection == nil {
		return nil, errors.New("peer connection not initialized")
	}

	channel, err := c.peerConnection.CreateDataChannel(label, options)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.dataChannels[label] = channel
	c.mu.Unlock()

	return channel, nil
}

func (c *WebRTCPeerConnection) CreateOfferWithCredentials(config *config.Config) (string, error) {
	control, err := c.peerConnection.CreateDataChannel("control", nil)
	if err != nil {
		return "", err
	}
	c.Control = control

	offer, err := c.peerConnection.CreateOffer(nil)
	if err != nil {
		return "", fmt.Errorf("failed to create temporary offer: %w", err)
	}

	err = c.peerConnection.SetLocalDescription(offer)
	if err != nil {
		return "", fmt.Errorf("failed to set local description: %w", err)
	}

	gatherComplete := pion.GatheringCompletePromise(c.peerConnection)
	<-gatherComplete

	offer, err = c.peerConnection.CreateOffer(nil)
	if err != nil {
		return "", fmt.Errorf("failed to create final offer: %w", err)
	}

	offerPayload := OfferPayload{
		OfferSDP:   offer.SDP,
		ICEServers: config.ICEServers,
	}

	jsonData, err := json.Marshal(offerPayload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal offer: %w", err)
	}

	compressedOffer, err := utils.CompressAndBase64Encode(jsonData)
	if err != nil {
		return "", fmt.Errorf("failed to compress offer: %w", err)
	}

	return compressedOffer, nil
}

func (c *WebRTCPeerConnection) HandleOfferGenerateAnswer(offer OfferPayload) (string, error) {
	offerSDP := pion.SessionDescription{
		Type: pion.SDPTypeOffer,
		SDP:  offer.OfferSDP,
	}

	err := c.peerConnection.SetRemoteDescription(offerSDP)
	if err != nil {
		return "", fmt.Errorf("failed to set remote description: %w", err)
	}

	answer, err := c.peerConnection.CreateAnswer(nil)
	if err != nil {
		return "", fmt.Errorf("failed to create answer: %w", err)
	}

	err = c.peerConnection.SetLocalDescription(answer)
	if err != nil {
		return "", fmt.Errorf("failed to set local description: %w", err)
	}

	gatherComplete := pion.GatheringCompletePromise(c.peerConnection)
	<-gatherComplete

	finalAnswer := c.peerConnection.LocalDescription().SDP

	compressedAnswer, err := utils.CompressAndBase64Encode([]byte(finalAnswer))
	if err != nil {
		return "", fmt.Errorf("failed to compress answer: %w", err)
	}

	return compressedAnswer, nil
}

func (c *WebRTCPeerConnection) HandleCompressedAnswer(compressedAnswer string) error {
	answer, err := utils.DecompressAndBase64Decode(compressedAnswer)
	if err != nil {
		return fmt.Errorf("failed to decompress answer: %w", err)
	}

	remoteSDP := pion.SessionDescription{
		Type: pion.SDPTypeAnswer,
		SDP:  string(answer),
	}

	err = c.peerConnection.SetRemoteDescription(remoteSDP)
	if err != nil {
		return fmt.Errorf("failed to set remote description: %w", err)
	}

	return nil
}

func (c *WebRTCPeerConnection) Close() error {
	if c.peerConnection == nil {
		return errors.New("peer connection not set")
	}

	return c.peerConnection.Close()
}

func (c *WebRTCPeerConnection) GetPeerConnection() *pion.PeerConnection {
	return c.peerConnection
}

func (c *WebRTCPeerConnection) GetConnectionState() pion.PeerConnectionState {
	if c.peerConnection == nil {
		return pion.PeerConnectionStateClosed
	}
	return c.peerConnection.ConnectionState()
}

func (c *WebRTCPeerConnection) GetSCTPState() pion.SCTPTransportState {
	if c.peerConnection == nil || c.peerConnection.SCTP() == nil {
		return pion.SCTPTransportStateClosed
	}
	return c.peerConnection.SCTP().State()
}

func DecodeCompressedOffer(compressedOffer string) (OfferPayload, error) {
	var offer OfferPayload

	offerPayloadJSON, err := utils.DecompressAndBase64Decode(compressedOffer)
	if err != nil {
		return offer, fmt.Errorf("failed to decompress offer: %w", err)
	}

	err = json.Unmarshal(offerPayloadJSON, &offer)
	if err != nil {
		return offer, fmt.Errorf("failed to unmarshal offer: %w", err)
	}

	return offer, nil
}

func (c *WebRTCPeerConnection) GetControlChannel() *pion.DataChannel {
	return c.Control
}

func (c *WebRTCPeerConnection) GetDataChannel(label string) *pion.DataChannel {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.dataChannels[label]
}
