package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

const (
	// Agent endpoints
	agentMetricsURL  = "http://localhost:9100/metrics"
	agentDropsURL    = "http://localhost:9100/api/drops"
	agentSessionsURL = "http://localhost:9100/api/sessions"
)

// TrafficStats represents traffic statistics
type TrafficStats struct {
	Uplink   DirectionStats `json:"uplink"`
	Downlink DirectionStats `json:"downlink"`
}

// DirectionStats represents stats for a single direction
type DirectionStats struct {
	Packets     uint64  `json:"packets"`
	Bytes       uint64  `json:"bytes"`
	Throughput  float64 `json:"throughput_mbps"`
	LastUpdated string  `json:"last_updated"`
}

// DropStats represents drop statistics
type DropStats struct {
	Total       uint64            `json:"total"`
	Rate        float64           `json:"rate_percent"`
	RecentDrops []DropEvent       `json:"recent_drops"`
	ByReason    map[string]uint64 `json:"by_reason"`
}

// DropEvent represents a single drop event
type DropEvent struct {
	Timestamp string `json:"timestamp"`
	TEID      string `json:"teid"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   uint16 `json:"src_port"`
	DstPort   uint16 `json:"dst_port"`
	Reason    string `json:"reason"`
	Direction string `json:"direction"`
	PktLen    uint32 `json:"pkt_len"`
}

// SessionInfo represents a PDU session (extended)
type SessionInfo struct {
	SEID      string   `json:"seid"`
	UEIP      string   `json:"ue_ip"`
	TEIDs     []string `json:"teids"`
	CreatedAt string   `json:"created_at"`
	PacketsUL uint64   `json:"packets_ul"`
	PacketsDL uint64   `json:"packets_dl"`

	// Extended fields
	UPFIP        string `json:"upf_ip,omitempty"`
	GNBIP        string `json:"gnb_ip,omitempty"`
	UplinkPeerIP string `json:"uplink_peer_ip,omitempty"`
	N9PeerIP     string `json:"n9_peer_ip,omitempty"` // N9 peer UPF IP (for ULCL)
	SUPI         string `json:"supi,omitempty"`
	DNN          string `json:"dnn,omitempty"`
	SNssai       string `json:"s_nssai,omitempty"`
	QFI          uint8  `json:"qfi,omitempty"`
	SessionType  string `json:"session_type,omitempty"`
	SessionID    uint8  `json:"pdu_session_id,omitempty"`

	// Traffic statistics
	BytesUL uint64 `json:"bytes_ul"`
	BytesDL uint64 `json:"bytes_dl"`

	// QoS parameters
	QoS5QI      uint8  `json:"qos_5qi,omitempty"`
	ARPPL       uint8  `json:"arp_priority,omitempty"`
	GBRUplink   uint64 `json:"gbr_ul_kbps,omitempty"`
	GBRDownlink uint64 `json:"gbr_dl_kbps,omitempty"`
	MBRUplink   uint64 `json:"mbr_ul_kbps,omitempty"`
	MBRDownlink uint64 `json:"mbr_dl_kbps,omitempty"`

	// Status
	Status     string `json:"status"`
	Duration   string `json:"duration,omitempty"`
	LastActive string `json:"last_active,omitempty"`
}

// Server represents the API server
type Server struct {
	router    *gin.Engine
	upgrader  websocket.Upgrader
	clients   map[*websocket.Conn]bool
	clientsMu sync.Mutex
	broadcast chan interface{}

	// In-memory stats (will be replaced with Prometheus queries)
	stats    TrafficStats
	drops    DropStats
	sessions []SessionInfo
	statsMu  sync.RWMutex
}

func main() {
	log.Println("============================================================")
	log.Println("    5G-DPOP: Backend API Server")
	log.Println("============================================================")

	server := NewServer()

	log.Println("[INFO] Starting API server on :8080")
	if err := server.Run(":8080"); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// NewServer creates a new API server
func NewServer() *Server {
	s := &Server{
		router: gin.Default(),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for development
			},
		},
		clients:   make(map[*websocket.Conn]bool),
		broadcast: make(chan interface{}),
		drops: DropStats{
			RecentDrops: make([]DropEvent, 0),
			ByReason:    make(map[string]uint64),
		},
		sessions: make([]SessionInfo, 0),
	}

	s.setupRoutes()
	go s.handleBroadcast()
	go s.collectMetricsFromAgent() // Start collecting metrics from agent

	return s
}

func (s *Server) setupRoutes() {
	// CORS middleware
	s.router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// API routes
	api := s.router.Group("/api/v1")
	{
		api.GET("/health", s.handleHealth)
		api.GET("/metrics/traffic", s.handleTrafficMetrics)
		api.GET("/metrics/drops", s.handleDropMetrics)
		api.GET("/sessions", s.handleSessions)
		api.GET("/sessions/:seid", s.handleSessionDetail)
		api.GET("/topology", s.handleTopology)
		api.POST("/fault/inject", s.handleFaultInject)

		// Proxy demo APIs to agent
		api.POST("/demo/inject-drop", s.proxyToAgent)
		api.POST("/demo/inject-session", s.proxyToAgent)
	}

	// WebSocket for real-time updates
	s.router.GET("/ws/metrics", s.handleWebSocket)
	s.router.GET("/ws/events", s.handleEventsWebSocket)
}

// Health check
func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "1.0.0",
	})
}

// Traffic metrics
func (s *Server) handleTrafficMetrics(c *gin.Context) {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()

	c.JSON(http.StatusOK, s.stats)
}

// Drop metrics
func (s *Server) handleDropMetrics(c *gin.Context) {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()

	c.JSON(http.StatusOK, s.drops)
}

// Sessions list
func (s *Server) handleSessions(c *gin.Context) {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"total":    len(s.sessions),
		"sessions": s.sessions,
	})
}

// Session detail
func (s *Server) handleSessionDetail(c *gin.Context) {
	seid := c.Param("seid")

	s.statsMu.RLock()
	defer s.statsMu.RUnlock()

	for _, session := range s.sessions {
		if session.SEID == seid {
			c.JSON(http.StatusOK, session)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{
		"error": "session not found",
	})
}

// Fault injection
func (s *Server) handleFaultInject(c *gin.Context) {
	var req struct {
		Type   string `json:"type"`   // "invalid_teid", "no_pdr"
		Target string `json:"target"` // Target TEID or IP
		Count  int    `json:"count"`  // Number of packets
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Implement actual fault injection
	log.Printf("[FAULT] Injection requested: type=%s, target=%s, count=%d",
		req.Type, req.Target, req.Count)

	c.JSON(http.StatusOK, gin.H{
		"status": "injection_started",
		"type":   req.Type,
		"target": req.Target,
	})
}

// proxyToAgent proxies demo API requests to the agent
func (s *Server) proxyToAgent(c *gin.Context) {
	// Build the agent URL (agent uses /api/ instead of /api/v1/)
	path := c.Request.URL.Path
	if strings.HasPrefix(path, "/api/v1/") {
		path = "/api/" + path[len("/api/v1/"):]
	}
	agentURL := "http://localhost:9100" + path
	if c.Request.URL.RawQuery != "" {
		agentURL += "?" + c.Request.URL.RawQuery
	}

	// Create request to agent
	req, err := http.NewRequest(c.Request.Method, agentURL, c.Request.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}
	req.Header.Set("Content-Type", c.GetHeader("Content-Type"))

	// Execute request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "Agent not available"})
		return
	}
	defer resp.Body.Close()

	// Copy response
	body, _ := io.ReadAll(resp.Body)
	c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), body)
}

// WebSocket handler for real-time metrics
func (s *Server) handleWebSocket(c *gin.Context) {
	conn, err := s.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	s.clientsMu.Lock()
	s.clients[conn] = true
	s.clientsMu.Unlock()

	defer func() {
		s.clientsMu.Lock()
		delete(s.clients, conn)
		s.clientsMu.Unlock()
		conn.Close()
	}()

	// Send initial data
	s.statsMu.RLock()
	conn.WriteJSON(gin.H{
		"type": "initial",
		"data": gin.H{
			"traffic":  s.stats,
			"drops":    s.drops,
			"sessions": len(s.sessions),
		},
	})
	s.statsMu.RUnlock()

	// Keep connection alive and handle client messages
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// WebSocket handler for events
func (s *Server) handleEventsWebSocket(c *gin.Context) {
	conn, err := s.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	s.clientsMu.Lock()
	s.clients[conn] = true
	s.clientsMu.Unlock()

	defer func() {
		s.clientsMu.Lock()
		delete(s.clients, conn)
		s.clientsMu.Unlock()
		conn.Close()
	}()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// Broadcast updates to all WebSocket clients
func (s *Server) handleBroadcast() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.statsMu.RLock()
		msg := gin.H{
			"type": "update",
			"data": gin.H{
				"traffic":  s.stats,
				"drops":    s.drops,
				"sessions": len(s.sessions),
			},
			"timestamp": time.Now().Format(time.RFC3339),
		}
		s.statsMu.RUnlock()

		s.clientsMu.Lock()
		for client := range s.clients {
			if err := client.WriteJSON(msg); err != nil {
				client.Close()
				delete(s.clients, client)
			}
		}
		s.clientsMu.Unlock()
	}
}

// UpdateStats updates the traffic statistics (called from agent)
func (s *Server) UpdateStats(stats TrafficStats) {
	s.statsMu.Lock()
	s.stats = stats
	s.statsMu.Unlock()
}

// AddDropEvent adds a drop event
func (s *Server) AddDropEvent(event DropEvent) {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()

	s.drops.Total++
	s.drops.RecentDrops = append([]DropEvent{event}, s.drops.RecentDrops...)

	// Keep only last 100 events
	if len(s.drops.RecentDrops) > 100 {
		s.drops.RecentDrops = s.drops.RecentDrops[:100]
	}

	s.drops.ByReason[event.Reason]++
}

// Run starts the server
func (s *Server) Run(addr string) error {
	return s.router.Run(addr)
}

// collectMetricsFromAgent periodically fetches metrics from the eBPF agent
func (s *Server) collectMetricsFromAgent() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var prevUplinkBytes, prevDownlinkBytes uint64
	var prevTime time.Time

	log.Println("[INFO] Starting metrics collection from agent at", agentMetricsURL)

	for range ticker.C {
		// Fetch Prometheus metrics for traffic
		metrics, err := s.fetchAgentMetrics()
		if err != nil {
			log.Printf("[WARN] Failed to fetch agent metrics: %v", err)
			continue
		}

		// Fetch drops from agent API
		dropsData, err := s.fetchAgentDrops()
		if err != nil {
			log.Printf("[WARN] Failed to fetch drops: %v", err)
		}

		// Fetch sessions from agent API
		sessionsData, err := s.fetchAgentSessions()
		if err != nil {
			log.Printf("[WARN] Failed to fetch sessions: %v", err)
		}

		now := time.Now()

		// Calculate throughput
		var uplinkThroughput, downlinkThroughput float64
		if !prevTime.IsZero() {
			elapsed := now.Sub(prevTime).Seconds()
			if elapsed > 0 {
				uplinkBytesDelta := metrics.uplinkBytes - prevUplinkBytes
				downlinkBytesDelta := metrics.downlinkBytes - prevDownlinkBytes
				uplinkThroughput = float64(uplinkBytesDelta*8) / elapsed / 1000000     // Mbps
				downlinkThroughput = float64(downlinkBytesDelta*8) / elapsed / 1000000 // Mbps
			}
		}

		prevUplinkBytes = metrics.uplinkBytes
		prevDownlinkBytes = metrics.downlinkBytes
		prevTime = now

		// Update stats
		s.statsMu.Lock()
		s.stats = TrafficStats{
			Uplink: DirectionStats{
				Packets:     metrics.uplinkPackets,
				Bytes:       metrics.uplinkBytes,
				Throughput:  uplinkThroughput,
				LastUpdated: now.Format(time.RFC3339),
			},
			Downlink: DirectionStats{
				Packets:     metrics.downlinkPackets,
				Bytes:       metrics.downlinkBytes,
				Throughput:  downlinkThroughput,
				LastUpdated: now.Format(time.RFC3339),
			},
		}

		// Update drop stats from agent API
		if dropsData != nil {
			s.drops = *dropsData
		}

		// Update sessions from agent API
		if sessionsData != nil {
			s.sessions = sessionsData
		}
		s.statsMu.Unlock()
	}
}

// fetchAgentDrops fetches drop events from agent API
func (s *Server) fetchAgentDrops() (*DropStats, error) {
	resp, err := http.Get(agentDropsURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch drops: %w", err)
	}
	defer resp.Body.Close()

	var dropsData DropStats
	if err := json.NewDecoder(resp.Body).Decode(&dropsData); err != nil {
		return nil, fmt.Errorf("failed to decode drops: %w", err)
	}

	return &dropsData, nil
}

// fetchAgentSessions fetches sessions from agent API
func (s *Server) fetchAgentSessions() ([]SessionInfo, error) {
	resp, err := http.Get(agentSessionsURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch sessions: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Total    int           `json:"total"`
		Sessions []SessionInfo `json:"sessions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode sessions: %w", err)
	}

	return result.Sessions, nil
}

// agentMetrics holds parsed metrics from the agent
type agentMetrics struct {
	uplinkPackets   uint64
	downlinkPackets uint64
	uplinkBytes     uint64
	downlinkBytes   uint64
	totalDrops      uint64
	activeSessions  uint64
}

// fetchAgentMetrics fetches and parses metrics from the eBPF agent
func (s *Server) fetchAgentMetrics() (*agentMetrics, error) {
	resp, err := http.Get(agentMetricsURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metrics: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return parsePrometheusMetrics(string(body))
}

// parsePrometheusMetrics parses Prometheus text format metrics
func parsePrometheusMetrics(body string) (*agentMetrics, error) {
	metrics := &agentMetrics{}

	// Regex patterns for different metric formats
	packetsPattern := regexp.MustCompile(`upf_packets_total\{direction="(\w+)"\}\s+([0-9.e+\-]+)`)
	bytesPattern := regexp.MustCompile(`upf_bytes_total\{direction="(\w+)"\}\s+([0-9.e+\-]+)`)
	dropsPattern := regexp.MustCompile(`upf_packet_drops_total\{[^}]*\}\s+([0-9.e+\-]+)`)
	sessionsPattern := regexp.MustCompile(`upf_active_sessions\s+([0-9.e+\-]+)`)

	// Parse packets
	for _, match := range packetsPattern.FindAllStringSubmatch(body, -1) {
		if len(match) == 3 {
			value := parseNumber(match[2])
			switch match[1] {
			case "uplink":
				metrics.uplinkPackets = value
			case "downlink":
				metrics.downlinkPackets = value
			}
		}
	}

	// Parse bytes
	for _, match := range bytesPattern.FindAllStringSubmatch(body, -1) {
		if len(match) == 3 {
			value := parseNumber(match[2])
			switch match[1] {
			case "uplink":
				metrics.uplinkBytes = value
			case "downlink":
				metrics.downlinkBytes = value
			}
		}
	}

	// Parse drops (sum all drop reasons)
	for _, match := range dropsPattern.FindAllStringSubmatch(body, -1) {
		if len(match) == 2 {
			value := parseNumber(match[1])
			metrics.totalDrops += value
		}
	}

	// Parse active sessions
	if match := sessionsPattern.FindStringSubmatch(body); len(match) == 2 {
		metrics.activeSessions = parseNumber(match[1])
	}

	return metrics, nil
}

// parseNumber parses both integer and scientific notation
func parseNumber(s string) uint64 {
	// Try parsing as float first (handles scientific notation)
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return uint64(f)
	}
	// Fall back to uint64
	if v, err := strconv.ParseUint(s, 10, 64); err == nil {
		return v
	}
	return 0
}

// Ensure json and other imports are used
var _ = json.Marshal

// TopologyNode represents a node in the topology
type TopologyNode struct {
	ID    string `json:"id"`
	Type  string `json:"type"` // "ue", "upf", "gnb", "dn"
	Label string `json:"label"`
	IP    string `json:"ip"`
}

// TopologyLink represents a link in the topology
type TopologyLink struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Label  string `json:"label"` // e.g. SEID
	Type   string `json:"type"`  // "n3", "n4", "n6", "n9"
}

// Topology represents the network topology
type Topology struct {
	Nodes []TopologyNode `json:"nodes"`
	Links []TopologyLink `json:"links"`
}

func (s *Server) handleTopology(c *gin.Context) {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()

	nodes := make(map[string]TopologyNode)
	links := make([]TopologyLink, 0)

	// Pass 1: Identify all UPFs and UEs first
	for _, session := range s.sessions {
		// UE Node
		if session.UEIP != "" {
			nodes[session.UEIP] = TopologyNode{
				ID:    session.UEIP,
				Type:  "ue",
				Label: "UE " + session.UEIP,
				IP:    session.UEIP,
			}
		}

		// UPF Node
		upfIP := session.UPFIP
		if upfIP == "" {
			upfIP = "UPF-Local" // Fallback
		}
		nodes[upfIP] = TopologyNode{
			ID:    upfIP,
			Type:  "upf",
			Label: "UPF " + upfIP,
			IP:    upfIP,
		}
	}

	// Pass 2: Identify Peers (gNB or other UPFs)
	for _, session := range s.sessions {
		upfIP := session.UPFIP
		if upfIP == "" {
			upfIP = "UPF-Local"
		}

		// Determine Access Peer (gNB)
		// Prefer UplinkPeerIP (actual source of UL traffic) if available
		accessPeerIP := session.UplinkPeerIP

		// Sanity check: Access Peer cannot be the UPF itself
		if accessPeerIP == upfIP {
			accessPeerIP = ""
		}

		if accessPeerIP == "" {
			accessPeerIP = session.GNBIP // Fallback to signaled IP
		}

		// Sanity check again
		if accessPeerIP == upfIP {
			accessPeerIP = ""
		}

		// Handle Access Peer (gNB)
		if accessPeerIP != "" {
			// Only create if not exists (don't overwrite UPF)
			if _, exists := nodes[accessPeerIP]; !exists {
				nodes[accessPeerIP] = TopologyNode{
					ID:    accessPeerIP,
					Type:  "gnb", // Default to gNB for access peer
					Label: "Peer " + accessPeerIP,
					IP:    accessPeerIP,
				}
			}

			// Link: Access Peer -> UPF (N3)
			links = append(links, TopologyLink{
				Source: accessPeerIP,
				Target: upfIP,
				Label:  "N3",
				Type:   "n3",
			})

			// Link: UE -> Access Peer (Radio)
			// Only create this link if we haven't already (to avoid duplicates)
			// And only if this session has a UE
			if session.UEIP != "" {
				links = append(links, TopologyLink{
					Source: session.UEIP,
					Target: accessPeerIP,
					Label:  "Radio",
					Type:   "radio",
				})
			}
		}

		// Handle Core Peer (PSA-UPF in ULCL scenario)
		// Use N9PeerIP if available (from Outer Header Creation pointing to another UPF)
		n9PeerIP := session.N9PeerIP
		if n9PeerIP == "" {
			// Fallback: If GNBIP is present and different from Access Peer, it might be the Core-side UPF
			if session.GNBIP != "" && session.GNBIP != accessPeerIP {
				n9PeerIP = session.GNBIP
			}
		}

		if n9PeerIP != "" {
			// Only create if not exists
			if _, exists := nodes[n9PeerIP]; !exists {
				nodes[n9PeerIP] = TopologyNode{
					ID:    n9PeerIP,
					Type:  "upf",
					Label: "UPF " + n9PeerIP,
					IP:    n9PeerIP,
				}
			}

			// Link: UPF -> N9 Peer UPF (N9)
			links = append(links, TopologyLink{
				Source: upfIP,
				Target: n9PeerIP,
				Label:  "N9",
				Type:   "n9",
			})
		}
	}

	// Add DN Node
	dnID := "DN-Internet"
	nodes[dnID] = TopologyNode{
		ID:    dnID,
		Type:  "dn",
		Label: "Data Network",
		IP:    "Internet",
	}

	// Link UPF -> DN (for each UPF)
	for _, n := range nodes {
		if n.Type == "upf" {
			links = append(links, TopologyLink{
				Source: n.ID,
				Target: dnID,
				Label:  "N6",
				Type:   "n6",
			})
		}
	}

	// Convert map to slice
	nodeList := make([]TopologyNode, 0, len(nodes))
	for _, n := range nodes {
		nodeList = append(nodeList, n)
	}

	c.JSON(http.StatusOK, Topology{
		Nodes: nodeList,
		Links: links,
	})
}
