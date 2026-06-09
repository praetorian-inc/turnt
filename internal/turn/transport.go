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
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// Transport abstracts the underlying network connection for STUN/TURN.
type Transport interface {
	Send(data []byte) (int, error)
	Recv(buf []byte) (int, error)
	Close() error
	SetDeadline(t time.Time) error
	LocalAddr() net.Addr
	Protocol() string
}

// TransportConfig holds connection parameters for creating transports.
type TransportConfig struct {
	ServerAddr string
	Protocol   string // "udp", "tcp", "tls"
	Timeout    time.Duration
	TLSConfig  *tls.Config
}

// DefaultPort returns the default port for a given protocol.
func DefaultPort(protocol string) string {
	switch protocol {
	case "tls":
		return "5349"
	default:
		return "3478"
	}
}

// ResolveAddr ensures the server address includes a port.
func ResolveAddr(addr, protocol string) string {
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		return net.JoinHostPort(addr, DefaultPort(protocol))
	}
	return addr
}

// NewTransport creates a Transport based on the protocol in config.
func NewTransport(cfg TransportConfig) (Transport, error) {
	addr := ResolveAddr(cfg.ServerAddr, cfg.Protocol)
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	switch cfg.Protocol {
	case "udp", "":
		return newUDPTransport(addr, timeout)
	case "tcp":
		return newTCPTransport(addr, timeout)
	case "tls":
		tlsCfg := cfg.TLSConfig
		if tlsCfg == nil {
			tlsCfg = &tls.Config{InsecureSkipVerify: true}
		}
		return newTLSTransport(addr, timeout, tlsCfg)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", cfg.Protocol)
	}
}

// UDPTransport sends/receives raw STUN datagrams over UDP.
type UDPTransport struct {
	conn *net.UDPConn
}

func newUDPTransport(addr string, timeout time.Duration) (*UDPTransport, error) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr: %w", err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("dial udp: %w", err)
	}
	return &UDPTransport{conn: conn}, nil
}

func (t *UDPTransport) Send(data []byte) (int, error) {
	return t.conn.Write(data)
}

func (t *UDPTransport) Recv(buf []byte) (int, error) {
	return t.conn.Read(buf)
}

func (t *UDPTransport) Close() error {
	return t.conn.Close()
}

func (t *UDPTransport) SetDeadline(d time.Time) error {
	return t.conn.SetDeadline(d)
}

func (t *UDPTransport) LocalAddr() net.Addr {
	return t.conn.LocalAddr()
}

func (t *UDPTransport) Protocol() string {
	return "udp"
}

// TCPTransport sends/receives STUN messages over TCP with 2-byte length prefix per RFC 6062.
type TCPTransport struct {
	conn net.Conn
}

func newTCPTransport(addr string, timeout time.Duration) (*TCPTransport, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial tcp: %w", err)
	}
	return &TCPTransport{conn: conn}, nil
}

func (t *TCPTransport) Send(data []byte) (int, error) {
	// Write 2-byte big-endian length prefix, then the message
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(data)))
	if _, err := t.conn.Write(lenBuf); err != nil {
		return 0, err
	}
	return t.conn.Write(data)
}

func (t *TCPTransport) Recv(buf []byte) (int, error) {
	// Read 2-byte length prefix
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(t.conn, lenBuf); err != nil {
		return 0, err
	}
	msgLen := int(binary.BigEndian.Uint16(lenBuf))
	if msgLen > len(buf) {
		return 0, fmt.Errorf("message too large: %d bytes (buffer: %d)", msgLen, len(buf))
	}
	return io.ReadFull(t.conn, buf[:msgLen])
}

func (t *TCPTransport) Close() error {
	return t.conn.Close()
}

func (t *TCPTransport) SetDeadline(d time.Time) error {
	return t.conn.SetDeadline(d)
}

func (t *TCPTransport) LocalAddr() net.Addr {
	return t.conn.LocalAddr()
}

func (t *TCPTransport) Protocol() string {
	return "tcp"
}

// TLSTransport sends/receives STUN messages over TLS with 2-byte length prefix.
type TLSTransport struct {
	conn *tls.Conn
}

func newTLSTransport(addr string, timeout time.Duration, config *tls.Config) (*TLSTransport, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("dial tls: %w", err)
	}
	return &TLSTransport{conn: conn}, nil
}

func (t *TLSTransport) Send(data []byte) (int, error) {
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(data)))
	if _, err := t.conn.Write(lenBuf); err != nil {
		return 0, err
	}
	return t.conn.Write(data)
}

func (t *TLSTransport) Recv(buf []byte) (int, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(t.conn, lenBuf); err != nil {
		return 0, err
	}
	msgLen := int(binary.BigEndian.Uint16(lenBuf))
	if msgLen > len(buf) {
		return 0, fmt.Errorf("message too large: %d bytes (buffer: %d)", msgLen, len(buf))
	}
	return io.ReadFull(t.conn, buf[:msgLen])
}

func (t *TLSTransport) Close() error {
	return t.conn.Close()
}

func (t *TLSTransport) SetDeadline(d time.Time) error {
	return t.conn.SetDeadline(d)
}

func (t *TLSTransport) LocalAddr() net.Addr {
	return t.conn.LocalAddr()
}

func (t *TLSTransport) Protocol() string {
	return "tls"
}
