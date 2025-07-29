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
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/pion/webrtc/v3"
	pion "github.com/pion/webrtc/v3"
	"github.com/praetorian-inc/turnt/internal/logger"
	"github.com/praetorian-inc/turnt/internal/utils"
)

type Connection struct {
	channel *webrtc.DataChannel // WebRTC data channel used to communicate with relay from controller
	client  net.Conn            // SOCKS client connection used to communicate with controller
	server  net.Conn            // SOCKS server connection used to communicate with SOCKS client from controller
	local   net.Addr            // Simulate local address for the connection initiated by the SOCKS client
	remote  net.Addr            // Remote address represents the address the SOCKS client is connecting to through the relay
}

func (s *SOCKS5Server) newConnection(networkType string, targetAddr string) (*Connection, error) {
	channel, err := s.transport.CreateDataChannel(uuid.New().String(), &pion.DataChannelInit{
		Ordered:    utils.PTR(true),
		Negotiated: utils.PTR(false),
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create channel: %v", err)
	}

	if !utils.ValidateNetworkType(networkType) {
		return nil, fmt.Errorf("invalid network type: %s", networkType)
	}

	address, _ := net.ResolveTCPAddr(networkType, targetAddr)
	client, server := net.Pipe()
	return &Connection{
		channel: channel,
		client:  client,
		server:  server,
		local:   &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0},
		remote:  address,
	}, nil
}

func (c *Connection) GetChannel() *webrtc.DataChannel {
	return c.channel
}

func (c *Connection) GetID() uint16 {
	return *c.channel.ID()
}

func (c *Connection) GetClientConnection() net.Conn {
	return c.client
}

func (c *Connection) GetServerConnection() net.Conn {
	return c.server
}

func (c *Connection) IsClosed() bool {
	return c.channel.ReadyState() == webrtc.DataChannelStateClosed
}

func (c *Connection) Close() error {
	return c.channel.Close()
}

func (c *Connection) Send(data []byte) error {
	if c.channel == nil || c.channel.ReadyState() != webrtc.DataChannelStateOpen {
		return fmt.Errorf("data channel not open")
	}
	return c.channel.Send(data)
}

func (c *Connection) LocalAddr() net.Addr {
	return c.local
}

func (c *Connection) RemoteAddr() net.Addr {
	return c.remote
}

func (c *Connection) Read(b []byte) (n int, err error) {
	logger.Debug("connection.Read: attempting to read %d bytes", len(b))

	n, err = c.client.Read(b)
	if err != nil {
		logger.Error("connection.Read error: %v", err)
		return n, err
	}

	logger.Debug("connection.Read: successfully read %d bytes (first few: % x)", n, b[:min(n, 16)])
	return n, nil
}

func (c *Connection) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		logger.Debug("connection.Write: attempting to write 0 bytes")
		return 0, nil
	}

	logger.Debug("connection.Write: attempting to write %d bytes (first few: % x)", len(b), b[:min(len(b), 16)])
	n, err = c.client.Write(b)
	if err != nil {
		logger.Error("connection.Write error: %v", err)
		return n, err
	}

	logger.Debug("connection.Write: successfully wrote %d bytes", n)
	return n, nil
}

func (c *Connection) SetDeadline(t time.Time) error {
	return c.client.SetDeadline(t)
}

func (c *Connection) SetReadDeadline(t time.Time) error {
	return c.client.SetReadDeadline(t)
}

func (c *Connection) SetWriteDeadline(t time.Time) error {
	return c.client.SetWriteDeadline(t)
}
