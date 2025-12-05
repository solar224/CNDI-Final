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

// FlowTraffic represents per-destination traffic for ULCL path differentiation
type FlowTraffic struct {
	DestIP     string `json:"dest_ip"`
	Packets    uint64 `json:"packets"`
	Bytes      uint64 `json:"bytes"`
	LastActive string `json:"last_active,omitempty"`
	OuterDst   string `json:"outer_dst,omitempty"` // Next hop UPF or gateway
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

	// Per-flow traffic (for ULCL path differentiation)
	FlowTraffic []FlowTraffic `json:"flow_traffic,omitempty"`

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
	Source           string  `json:"source"`
	Target           string  `json:"target"`
	Label            string  `json:"label"`              // e.g. SEID
	Type             string  `json:"type"`               // "n3", "n4", "n6", "n9", "radio"
	HasActiveTraffic bool    `json:"hasActiveTraffic"`   // Whether there's active traffic
	TrafficRate      float64 `json:"trafficRate"`        // Traffic rate in bytes/sec
	LastSeen         string  `json:"lastSeen,omitempty"` // Timestamp of last traffic
}

// Topology represents the network topology
type Topology struct {
	Nodes []TopologyNode `json:"nodes"`
	Links []TopologyLink `json:"links"`
}

// isSessionActive checks if a session has recent traffic activity
// A session is considered active if it has traffic in the last 10 seconds
func isSessionActive(session SessionInfo) bool {
	if session.LastActive == "" {
		// No LastActive timestamp - check if there's any traffic
		return session.PacketsUL > 0 || session.PacketsDL > 0
	}

	// Parse LastActive timestamp
	lastActive, err := time.Parse(time.RFC3339, session.LastActive)
	if err != nil {
		// If parsing fails, fall back to checking packet count
		return session.PacketsUL > 0 || session.PacketsDL > 0
	}

	// Consider active if last activity was within 10 seconds
	return time.Since(lastActive) < 10*time.Second
}

// isFlowActive checks if a specific flow (destination) has recent traffic
func isFlowActive(flow FlowTraffic) bool {
	if flow.LastActive == "" {
		return flow.Packets > 0
	}

	lastActive, err := time.Parse(time.RFC3339, flow.LastActive)
	if err != nil {
		return flow.Packets > 0
	}

	// Consider active if last activity was within 10 seconds
	return time.Since(lastActive) < 10*time.Second
}

// getActiveFlowsByOuterDst groups active flows by their outer destination (next hop)
// This allows us to determine which UPF paths have active traffic
func getActiveFlowsByOuterDst(session SessionInfo) map[string]bool {
	result := make(map[string]bool)
	for _, flow := range session.FlowTraffic {
		if isFlowActive(flow) && flow.OuterDst != "" {
			result[flow.OuterDst] = true
		}
	}
	return result
}

// hasActiveFlowToN9Peer checks if session has active traffic going through N9 (to PSA-UPF)
func hasActiveFlowToN9Peer(session SessionInfo) bool {
	if session.N9PeerIP == "" {
		return false
	}
	for _, flow := range session.FlowTraffic {
		if isFlowActive(flow) && flow.OuterDst == session.N9PeerIP {
			return true
		}
	}
	return false
}

// hasActiveFlowToLocalBreakout checks if session has active traffic NOT going through N9
// (i.e., local breakout traffic that exits directly from I-UPF)
func hasActiveFlowToLocalBreakout(session SessionInfo) bool {
	for _, flow := range session.FlowTraffic {
		if isFlowActive(flow) {
			// If OuterDst is empty or not N9PeerIP, it's local breakout
			if flow.OuterDst == "" || flow.OuterDst != session.N9PeerIP {
				return true
			}
		}
	}
	// If no flow tracking data and this is a ULCL session (has N9PeerIP),
	// we can't determine if it's local breakout - return true for I-UPF N6
	// since all traffic goes through I-UPF first
	if len(session.FlowTraffic) == 0 && session.N9PeerIP != "" {
		return isSessionActive(session)
	}
	// For non-ULCL sessions, fall back to session-level activity
	if len(session.FlowTraffic) == 0 && session.N9PeerIP == "" {
		return isSessionActive(session)
	}
	return false
}

// calculateTrafficRate calculates bytes per second for a session
func calculateTrafficRate(session SessionInfo) float64 {
	// Simple calculation: total bytes / session duration
	if session.CreatedAt == "" {
		return 0
	}

	created, err := time.Parse(time.RFC3339, session.CreatedAt)
	if err != nil {
		return 0
	}

	duration := time.Since(created).Seconds()
	if duration <= 0 {
		return 0
	}

	totalBytes := float64(session.BytesUL + session.BytesDL)
	return totalBytes / duration
}

func (s *Server) handleTopology(c *gin.Context) {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()

	nodes := make(map[string]TopologyNode)
	links := make([]TopologyLink, 0)

	// Track which links have active traffic (key: "source->target")
	activeLinkTraffic := make(map[string]struct {
		active      bool
		trafficRate float64
		lastSeen    string
	})

	// First, identify all UPFs from N9PeerIP (these are definitely UPFs)
	upfIPs := make(map[string]bool)
	for _, session := range s.sessions {
		if session.UPFIP != "" {
			upfIPs[session.UPFIP] = true
		}
		if session.N9PeerIP != "" {
			upfIPs[session.N9PeerIP] = true
		}
		// UplinkPeerIP could be gNB or I-UPF - we'll determine later
	}

	// Pass 1: Create all nodes
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

		// UPF Node (from session)
		upfIP := session.UPFIP
		if upfIP == "" {
			upfIP = "UPF-Local"
		}
		nodes[upfIP] = TopologyNode{
			ID:    upfIP,
			Type:  "upf",
			Label: "UPF " + upfIP,
			IP:    upfIP,
		}

		// N9 Peer UPF (definitely a UPF in ULCL)
		if session.N9PeerIP != "" {
			nodes[session.N9PeerIP] = TopologyNode{
				ID:    session.N9PeerIP,
				Type:  "upf",
				Label: "UPF " + session.N9PeerIP,
				IP:    session.N9PeerIP,
			}
		}

		// Determine if UplinkPeerIP is gNB or UPF
		// If UplinkPeerIP == N9PeerIP, it's an I-UPF (already added above)
		// If UplinkPeerIP is in upfIPs, it's a UPF
		// Otherwise, it's likely the gNB
		uplinkPeer := session.UplinkPeerIP
		if uplinkPeer != "" && uplinkPeer != session.N9PeerIP && !upfIPs[uplinkPeer] {
			// This is likely the gNB
			if _, exists := nodes[uplinkPeer]; !exists {
				nodes[uplinkPeer] = TopologyNode{
					ID:    uplinkPeer,
					Type:  "gnb",
					Label: "gNB " + uplinkPeer,
					IP:    uplinkPeer,
				}
			}
		}

		// Also check GNBIP (signaled gNB address)
		if session.GNBIP != "" && !upfIPs[session.GNBIP] {
			if _, exists := nodes[session.GNBIP]; !exists {
				nodes[session.GNBIP] = TopologyNode{
					ID:    session.GNBIP,
					Type:  "gnb",
					Label: "gNB " + session.GNBIP,
					IP:    session.GNBIP,
				}
			}
		}
	}

	// Pass 2: Calculate traffic activity for each session's links
	for _, session := range s.sessions {
		upfIP := session.UPFIP
		if upfIP == "" {
			upfIP = "UPF-Local"
		}

		sessionActive := isSessionActive(session)
		trafficRate := calculateTrafficRate(session)

		// Determine gNB (the actual radio access point)
		gnbIP := session.GNBIP

		// Determine I-UPF (intermediate UPF in ULCL)
		// In ULCL: gNB -> I-UPF -> PSA-UPF -> DN
		// UplinkPeerIP from PSA-UPF's perspective is I-UPF
		iUpfIP := ""
		if session.N9PeerIP != "" && session.N9PeerIP != upfIP {
			iUpfIP = session.N9PeerIP
		} else if session.UplinkPeerIP != "" && upfIPs[session.UplinkPeerIP] {
			iUpfIP = session.UplinkPeerIP
		}

		// Link: UE -> gNB (Radio)
		if session.UEIP != "" && gnbIP != "" {
			linkKey := session.UEIP + "->" + gnbIP
			if existing, ok := activeLinkTraffic[linkKey]; !ok || sessionActive {
				activeLinkTraffic[linkKey] = struct {
					active      bool
					trafficRate float64
					lastSeen    string
				}{
					active:      existing.active || sessionActive,
					trafficRate: existing.trafficRate + trafficRate,
					lastSeen:    session.LastActive,
				}
			}
		}

		// Link: gNB -> I-UPF (N3) or gNB -> UPF (N3 if no ULCL)
		if gnbIP != "" {
			targetUPF := upfIP
			if iUpfIP != "" {
				targetUPF = iUpfIP
			}
			linkKey := gnbIP + "->" + targetUPF
			if existing, ok := activeLinkTraffic[linkKey]; !ok || sessionActive {
				activeLinkTraffic[linkKey] = struct {
					active      bool
					trafficRate float64
					lastSeen    string
				}{
					active:      existing.active || sessionActive,
					trafficRate: existing.trafficRate + trafficRate,
					lastSeen:    session.LastActive,
				}
			}
		}

		// Link: I-UPF -> PSA-UPF (N9) - only in ULCL
		if iUpfIP != "" && iUpfIP != upfIP {
			linkKey := iUpfIP + "->" + upfIP
			if existing, ok := activeLinkTraffic[linkKey]; !ok || sessionActive {
				activeLinkTraffic[linkKey] = struct {
					active      bool
					trafficRate float64
					lastSeen    string
				}{
					active:      existing.active || sessionActive,
					trafficRate: existing.trafficRate + trafficRate,
					lastSeen:    session.LastActive,
				}
			}
		}
	}

	// Pass 3: Create links with activity information
	linkSet := make(map[string]bool)

	for _, session := range s.sessions {
		upfIP := session.UPFIP
		if upfIP == "" {
			upfIP = "UPF-Local"
		}

		sessionActive := isSessionActive(session)
		gnbIP := session.GNBIP

		// Determine I-UPF
		iUpfIP := ""
		if session.N9PeerIP != "" && session.N9PeerIP != upfIP {
			iUpfIP = session.N9PeerIP
		} else if session.UplinkPeerIP != "" && upfIPs[session.UplinkPeerIP] {
			iUpfIP = session.UplinkPeerIP
		}

		// Radio Link: UE -> gNB
		if session.UEIP != "" && gnbIP != "" {
			linkKey := session.UEIP + "->" + gnbIP
			if !linkSet[linkKey] {
				linkSet[linkKey] = true
				activity := activeLinkTraffic[linkKey]
				links = append(links, TopologyLink{
					Source:           session.UEIP,
					Target:           gnbIP,
					Label:            "Radio",
					Type:             "radio",
					HasActiveTraffic: activity.active || sessionActive,
					TrafficRate:      activity.trafficRate,
					LastSeen:         activity.lastSeen,
				})
			}
		}

		// N3 Link: gNB -> I-UPF (or gNB -> UPF if no ULCL)
		if gnbIP != "" {
			targetUPF := upfIP
			if iUpfIP != "" {
				targetUPF = iUpfIP
			}
			linkKey := gnbIP + "->" + targetUPF
			if !linkSet[linkKey] {
				linkSet[linkKey] = true
				activity := activeLinkTraffic[linkKey]
				links = append(links, TopologyLink{
					Source:           gnbIP,
					Target:           targetUPF,
					Label:            "N3",
					Type:             "n3",
					HasActiveTraffic: activity.active || sessionActive,
					TrafficRate:      activity.trafficRate,
					LastSeen:         activity.lastSeen,
				})
			}
		}

		// N9 Link: I-UPF -> PSA-UPF (only in ULCL)
		// This link is active only when there's traffic going through N9 to PSA
		if iUpfIP != "" && iUpfIP != upfIP {
			linkKey := iUpfIP + "->" + upfIP
			if !linkSet[linkKey] {
				linkSet[linkKey] = true
				activity := activeLinkTraffic[linkKey]

				// Use per-flow tracking to determine N9 activity
				// Without per-flow data, N9 should NOT be active by default
				// because we can't distinguish local breakout from anchor traffic
				n9Active := hasActiveFlowToN9Peer(session)
				// Note: NO fallback - if no flow data, N9 stays inactive
				// This prevents all paths from lighting up when we can't track flows

				links = append(links, TopologyLink{
					Source:           iUpfIP,
					Target:           upfIP,
					Label:            "N9",
					Type:             "n9",
					HasActiveTraffic: n9Active,
					TrafficRate:      activity.trafficRate,
					LastSeen:         activity.lastSeen,
				})
			}
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

	// N6 Link: UPF -> DN
	// In ULCL architecture:
	// - I-UPF N6 link is active only for Local Breakout traffic (not going through N9)
	// - PSA-UPF N6 link is active only for traffic that came through N9

	// Track per-UPF activity based on flow-level tracking
	upfLocalActivity := make(map[string]bool) // For I-UPF local breakout
	upfN9Activity := make(map[string]bool)    // For PSA-UPF (traffic via N9)
	upfTrafficRate := make(map[string]float64)

	for _, session := range s.sessions {
		upfIP := session.UPFIP
		if upfIP == "" {
			upfIP = "UPF-Local"
		}

		// Check for local breakout activity (I-UPF direct to DN)
		if hasActiveFlowToLocalBreakout(session) {
			// If this session has an I-UPF (N9PeerIP != ""), mark I-UPF as having local activity
			if session.N9PeerIP != "" {
				upfLocalActivity[session.N9PeerIP] = true
			} else {
				// No ULCL, mark main UPF as active
				upfLocalActivity[upfIP] = true
			}
		}

		// Check for N9 activity (traffic going to PSA-UPF)
		if hasActiveFlowToN9Peer(session) {
			// Mark PSA-UPF as active (traffic is coming from I-UPF via N9)
			upfN9Activity[upfIP] = true
		}

		upfTrafficRate[upfIP] += calculateTrafficRate(session)
	}

	// Add N6 link for all UPFs with flow-aware activity
	for _, n := range nodes {
		if n.Type == "upf" {
			linkKey := n.ID + "->" + dnID
			if !linkSet[linkKey] {
				linkSet[linkKey] = true

				// Determine if this UPF's N6 link has active traffic
				// Check both local breakout activity and N9-forwarded activity
				hasActive := upfLocalActivity[n.ID] || upfN9Activity[n.ID]

				// Note: No general fallback for N6 in ULCL mode
				// upfLocalActivity is already set for I-UPF when session is active
				// PSA-UPF N6 only lights up when we have flow data showing N9 traffic

				links = append(links, TopologyLink{
					Source:           n.ID,
					Target:           dnID,
					Label:            "N6",
					Type:             "n6",
					HasActiveTraffic: hasActive,
					TrafficRate:      upfTrafficRate[n.ID],
				})
			}
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
