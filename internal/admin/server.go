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

package admin

import (
	"context"
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/praetorian-inc/turnt/internal/logger"
	"github.com/praetorian-inc/turnt/internal/lportfwd"
	"github.com/praetorian-inc/turnt/internal/socks"
	"github.com/quic-go/quic-go"
)

// Command represents an admin command
type Command struct {
	Type    string
	Args    []string
	Payload map[string]interface{}
}

// Response represents a command response
type Response struct {
	Success bool
	Message string
	Data    map[string]interface{}
}

// Server represents the admin interface server
type Server struct {
	listener    *quic.Listener
	addr        string
	handlers    map[string]CommandHandler
	mu          sync.RWMutex
	socksServer *socks.SOCKS5Server
}

// CommandHandler is a function that handles a specific command
type CommandHandler func(cmd Command) Response

func init() {
	gob.Register(Command{})
	gob.Register(Response{})
	gob.Register([]LocalPortForward{})
	gob.Register([]lportfwd.Forward{})
	gob.Register([]RemotePortForward{})
	gob.Register([]socks.PortForward{})
}

// NewServer creates a new admin server
func NewServer() *Server {
	s := &Server{
		addr:     "localhost:1337",
		handlers: make(map[string]CommandHandler),
	}

	// Register keepalive handler
	s.RegisterHandler("keepalive", func(cmd Command) Response {
		return Response{
			Success: true,
		}
	})

	return s
}

// SetSOCKS5Server sets the SOCKS5 server for the admin server
func (s *Server) SetSOCKS5Server(server *socks.SOCKS5Server) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.socksServer = server
}

// RegisterHandler registers a command handler
func (s *Server) RegisterHandler(cmdType string, handler CommandHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[cmdType] = handler
}

// Start starts the admin server
func (s *Server) Start(ctx context.Context) error {
	tlsConf := &quic.Config{
		KeepAlivePeriod: 0, // Disable keepalive for admin interface
	}

	listener, err := quic.ListenAddr(s.addr, generateTLSConfig(), tlsConf)
	if err != nil {
		return fmt.Errorf("failed to start QUIC listener: %w", err)
	}
	s.listener = listener

	log.Printf("Admin interface listening on %s", s.addr)

	go s.acceptLoop(ctx)
	return nil
}

// Stop stops the admin server
func (s *Server) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) acceptLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn, err := s.listener.Accept(ctx)
			if err != nil {
				if err != net.ErrClosed {
					log.Printf("Failed to accept connection: %v", err)
				}
				continue
			}
			go s.handleConnection(conn)
		}
	}
}

func (s *Server) handleConnection(conn quic.Connection) {
	logger.Info("New admin client connected from %s", conn.RemoteAddr())
	defer func() {
		conn.CloseWithError(0, "server closing")
		logger.Info("Admin client disconnected from %s", conn.RemoteAddr())
	}()

	// Accept the main command stream
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		logger.Error("Failed to accept stream: %v", err)
		return
	}
	defer stream.Close()

	// Accept the keepalive stream
	keepaliveStream, err := conn.AcceptStream(context.Background())
	if err != nil {
		logger.Error("Failed to accept keepalive stream: %v", err)
		return
	}
	defer keepaliveStream.Close()

	encoder := gob.NewEncoder(stream)
	decoder := gob.NewDecoder(stream)
	keepaliveEncoder := gob.NewEncoder(keepaliveStream)
	keepaliveDecoder := gob.NewDecoder(keepaliveStream)

	// Start keepalive handler
	go func() {
		for {
			var cmd Command
			if err := keepaliveDecoder.Decode(&cmd); err != nil {
				logger.Error("Failed to decode keepalive command: %v", err)
				return
			}

			if cmd.Type != "keepalive" {
				logger.Error("Received non-keepalive command on keepalive stream: %s", cmd.Type)
				continue
			}

			response := Response{
				Success: true,
			}
			if err := keepaliveEncoder.Encode(response); err != nil {
				logger.Error("Failed to send keepalive response: %v", err)
				return
			}
		}
	}()

	// Handle main command stream
	for {
		var cmd Command
		if err := decoder.Decode(&cmd); err != nil {
			logger.Error("Failed to decode command: %v", err)
			return
		}

		logger.Debug("Received command: Type='%s', Args=%v", cmd.Type, cmd.Args)

		handler, exists := s.handlers[cmd.Type]
		if !exists {
			logger.Error("Unknown command type: %s", cmd.Type)
			if err := encoder.Encode(Response{
				Success: false,
				Message: fmt.Sprintf("Unknown command: %s", cmd.Type),
			}); err != nil {
				logger.Error("Failed to send error response: %v", err)
				return
			}
			continue
		}

		response := handler(cmd)
		logger.Debug("Sending response: Success=%v, Message='%s'", response.Success, response.Message)

		if err := encoder.Encode(response); err != nil {
			logger.Error("Failed to send response: %v", err)
			return
		}
	}
}
