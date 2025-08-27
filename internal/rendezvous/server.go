package rendezvous

import (
	"fmt"
	"net/http"
	"sync"
)

const RendezvousPort = "13337"

// Server is a simple HTTP server that maps a code to a port.
type Server struct {
	httpServer *http.Server
	portMap    map[string]string
	mu         sync.RWMutex
}

// NewServer creates a new rendezvous server.
func NewServer() *Server {
	s := &Server{
		portMap: make(map[string]string),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)
	s.httpServer = &http.Server{
		Addr:    ":" + RendezvousPort,
		Handler: mux,
	}
	return s
}

// handleRequest is the HTTP handler. It looks up the code and returns the port.
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Path[1:] // Trim leading "/"
	s.mu.RLock()
	port, ok := s.portMap[code]
	s.mu.RUnlock()

	if !ok {
		http.NotFound(w, r)
		return
	}
	fmt.Fprint(w, port)
}

// Start runs the HTTP server in a new goroutine.
func (s *Server) Start() {
	go func() {
		// This will block until the server is closed. Errors are expected on shutdown.
		_ = s.httpServer.ListenAndServe()
	}()
}

// Stop gracefully shuts down the HTTP server.
func (s *Server) Stop() error {
	return s.httpServer.Close()
}

// Register maps a code to a specific port.
func (s *Server) Register(code, port string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.portMap[code] = port
}
