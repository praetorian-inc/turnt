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

package socks

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/webrtc/v3"
	"github.com/praetorian-inc/turnt/internal/logger"
	"github.com/praetorian-inc/turnt/internal/utils"
)

type DNSRequest struct {
	Hostname string `json:"hostname"`
	ID       uint32 `json:"id"`
}

type DNSResponse struct {
	Hostname string   `json:"hostname"`
	IPs      []string `json:"ips"`
	Error    string   `json:"error,omitempty"`
	ID       uint32   `json:"id"`
}

type DNSResolver struct {
	peerConn    *webrtc.PeerConnection
	channel     *webrtc.DataChannel
	requestMap  map[uint32]chan DNSResponse
	requestMux  sync.RWMutex
	nextRequest uint32
	idMutex     sync.Mutex
	ready       chan struct{}
}

func NewDNSResolver(peerConn *webrtc.PeerConnection) *DNSResolver {
	return &DNSResolver{
		peerConn:    peerConn,
		requestMap:  make(map[uint32]chan DNSResponse),
		nextRequest: 1,
		ready:       make(chan struct{}),
	}
}

func (r *DNSResolver) Start() error {
	logger.Debug("Creating new DNS data channel")
	channel, err := r.peerConn.CreateDataChannel("dns", &webrtc.DataChannelInit{
		Ordered:    utils.PTR(true),
		Negotiated: utils.PTR(false),
	})
	if err != nil {
		return fmt.Errorf("failed to create DNS data channel: %v", err)
	}

	r.channel = channel

	go func() {
		logger.Debug("Waiting for DNS channel to open...")
		for {
			if r.channel.ReadyState() == webrtc.DataChannelStateOpen {
				logger.Debug("DNS channel is now open")
				close(r.ready)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	r.channel.OnMessage(func(msg webrtc.DataChannelMessage) {
		var response DNSResponse
		if err := json.Unmarshal(msg.Data, &response); err != nil {
			logger.Error("Failed to decode DNS response: %v", err)
			return
		}

		r.requestMux.RLock()
		ch, exists := r.requestMap[response.ID]
		r.requestMux.RUnlock()

		if !exists {
			logger.Error("Received DNS response for unknown request ID: %d", response.ID)
			return
		}

		ch <- response

		r.requestMux.Lock()
		delete(r.requestMap, response.ID)
		r.requestMux.Unlock()
	})

	return nil
}

func (r *DNSResolver) WaitReady() {
	logger.Debug("DNS resolver waiting for ready signal...")
	timeout := time.After(30 * time.Second)

	select {
	case <-r.ready:
		logger.Debug("DNS resolver received ready signal")
	case <-timeout:
		logger.Error("Timeout waiting for DNS resolver ready signal, proceeding anyway...")
	}
}

func (r *DNSResolver) Resolve(hostname string) ([]string, error) {
	if r.channel == nil {
		logger.Info("DNS channel not initialized, using standard resolver for %s", hostname)
		return net.LookupHost(hostname)
	}

	if r.channel.ReadyState() != webrtc.DataChannelStateOpen {
		logger.Info("DNS channel not open, using standard resolver for %s", hostname)
		return net.LookupHost(hostname)
	}

	logger.Info("Using WebRTC DNS resolver for %s", hostname)

	r.idMutex.Lock()
	requestID := r.nextRequest
	r.nextRequest++
	r.idMutex.Unlock()

	responseChan := make(chan DNSResponse, 1)

	r.requestMux.Lock()
	r.requestMap[requestID] = responseChan
	r.requestMux.Unlock()

	request := DNSRequest{
		Hostname: hostname,
		ID:       requestID,
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		r.requestMux.Lock()
		delete(r.requestMap, requestID)
		r.requestMux.Unlock()
		return nil, fmt.Errorf("failed to encode DNS request: %v", err)
	}

	if err := r.channel.Send(requestBytes); err != nil {
		r.requestMux.Lock()
		delete(r.requestMap, requestID)
		r.requestMux.Unlock()
		logger.Info("Failed to send DNS request: %v, falling back to standard resolver for %s", err, hostname)
		return net.LookupHost(hostname)
	}

	timeout := time.After(5 * time.Second)

	select {
	case response := <-responseChan:
		if response.Error != "" {
			logger.Error("DNS resolution error for %s: %s", hostname, response.Error)
			return nil, fmt.Errorf("DNS resolution error: %s", response.Error)
		}
		logger.Info("WebRTC DNS resolution successful for %s: %v", hostname, response.IPs)
		return response.IPs, nil
	case <-timeout:
		r.requestMux.Lock()
		delete(r.requestMap, requestID)
		r.requestMux.Unlock()
		logger.Info("Timeout waiting for DNS response, falling back to standard resolver for %s", hostname)
		return net.LookupHost(hostname)
	}
}

func (r *DNSResolver) HandleDNSRequest(request DNSRequest) {
	if r.channel == nil {
		logger.Error("Cannot handle DNS request: channel not initialized")
		return
	}

	logger.Info("Handling DNS request for hostname: %s", request.Hostname)

	ips, err := net.LookupHost(request.Hostname)

	response := DNSResponse{
		Hostname: request.Hostname,
		ID:       request.ID,
	}

	if err != nil {
		logger.Error("DNS resolution error for %s: %v", request.Hostname, err)
		response.Error = err.Error()
	} else {
		logger.Info("DNS resolution successful for %s: %v", request.Hostname, ips)
		response.IPs = ips
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		logger.Error("Failed to encode DNS response: %v", err)
		return
	}

	if err := r.channel.Send(responseBytes); err != nil {
		logger.Error("Failed to send DNS response: %v", err)
		return
	}

	logger.Info("Sent DNS response for %s", request.Hostname)
}

func (r *DNSResolver) Close() {
	if r.channel != nil {
		r.channel.Close()
	}
}

type WebRTCResolver struct {
	dnsResolver *DNSResolver
}

func NewWebRTCResolver(dnsResolver *DNSResolver) *WebRTCResolver {
	return &WebRTCResolver{
		dnsResolver: dnsResolver,
	}
}

func (r *WebRTCResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	logger.Info("Resolving hostname via WebRTC resolver: %s", name)

	ips, err := r.dnsResolver.Resolve(name)
	if err != nil {
		logger.Error("Failed to resolve hostname %s: %v", name, err)
		return ctx, nil, err
	}

	if len(ips) == 0 {
		logger.Error("No IP addresses found for hostname: %s", name)
		return ctx, nil, fmt.Errorf("no IP addresses found for hostname: %s", name)
	}

	ip := net.ParseIP(ips[0])
	if ip == nil {
		logger.Error("Invalid IP address returned: %s", ips[0])
		return ctx, nil, fmt.Errorf("invalid IP address returned: %s", ips[0])
	}

	logger.Info("Resolved %s to %s", name, ip.String())
	return ctx, ip, nil
}
