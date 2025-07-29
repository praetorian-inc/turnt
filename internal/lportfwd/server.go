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

package lportfwd

import (
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/net/proxy"
)

// Forward represents a local port forward
type Forward struct {
	LHost    string
	LPort    string
	RHost    string
	RPort    string
	conn     net.Conn
	listener net.Listener
}

// Server manages local port forwards
type Server struct {
	forwards  map[string]*Forward
	mu        sync.RWMutex
	socksAddr string
}

// NewServer creates a new local port forward server
func NewServer(socksAddr string) *Server {
	return &Server{
		forwards:  make(map[string]*Forward),
		socksAddr: socksAddr,
	}
}

// AddForward adds a new local port forward
func (s *Server) AddForward(lhost, lport, rhost, rport string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create a unique key for this forward
	key := fmt.Sprintf("%s:%s", lhost, lport)
	if _, exists := s.forwards[key]; exists {
		return fmt.Errorf("port forward already exists for %s", key)
	}

	f := &Forward{
		LHost: lhost,
		LPort: lport,
		RHost: rhost,
		RPort: rport,
	}

	// Start listening for connections
	listener, err := net.Listen("tcp", net.JoinHostPort(lhost, lport))
	if err != nil {
		return fmt.Errorf("failed to listen on %s:%s: %v", lhost, lport, err)
	}

	go s.handleListener(listener, f)
	s.forwards[key] = f

	return nil
}

// RemoveForward removes a local port forward
func (s *Server) RemoveForward(port string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Try to find and remove the forward by port
	for key, f := range s.forwards {
		if f.LPort == port {
			// Close the listener
			if f.listener != nil {
				f.listener.Close()
			}
			// Close any active connections
			if f.conn != nil {
				f.conn.Close()
			}
			// Remove from the map
			delete(s.forwards, key)
			return nil
		}
	}

	return fmt.Errorf("no port forward found for local port %s", port)
}

// ListForwards returns a list of active port forwards
func (s *Server) ListForwards() []Forward {
	s.mu.RLock()
	defer s.mu.RUnlock()

	forwards := make([]Forward, 0, len(s.forwards))
	for _, f := range s.forwards {
		forwards = append(forwards, *f)
	}
	return forwards
}

func (s *Server) handleListener(listener net.Listener, f *Forward) {
	f.listener = listener
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Listener closed
			return
		}

		go s.handleConnection(conn, f)
	}
}

func (s *Server) handleConnection(conn net.Conn, f *Forward) {
	defer conn.Close()

	// Create a new SOCKS5 dialer using the configured SOCKS address
	dialer, err := proxy.SOCKS5("tcp", s.socksAddr, nil, proxy.Direct)
	if err != nil {
		fmt.Printf("Failed to create SOCKS5 dialer: %v\n", err)
		return
	}

	// Connect to remote host through SOCKS proxy
	remoteConn, err := dialer.Dial("tcp", net.JoinHostPort(f.RHost, f.RPort))
	if err != nil {
		fmt.Printf("Failed to connect to remote host: %v\n", err)
		return
	}
	defer remoteConn.Close()

	// Start bidirectional forwarding
	done := make(chan struct{})
	go func() {
		io.Copy(conn, remoteConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(remoteConn, conn)
		done <- struct{}{}
	}()

	// Wait for either direction to complete
	<-done
}
