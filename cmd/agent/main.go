package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/solar224/5G-DPOP/internal/ebpf"
	"github.com/solar224/5G-DPOP/internal/pfcp"
)

var (
	// Command line flags
	pfcpIface = flag.String("pfcp-iface", "lo", "Interface to capture PFCP packets")

	// Prometheus metrics
	packetsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "upf_packets_total",
			Help: "Total number of packets processed by UPF",
		},
		[]string{"direction"},
	)

	bytesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "upf_bytes_total",
			Help: "Total bytes processed by UPF",
		},
		[]string{"direction"},
	)

	packetDropsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "upf_packet_drops_total",
			Help: "Total number of dropped packets",
		},
		[]string{"reason", "direction"},
	)

	activeSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "upf_active_sessions",
			Help: "Number of active PDU sessions",
		},
	)

	// Drop events storage
	dropEventsMu  sync.RWMutex
	recentDrops   []DropEventJSON
	totalDrops    uint64
	dropsByReason = make(map[string]uint64)

	// PFCP correlation
	pfcpCorrelation *pfcp.Correlation

	// Global eBPF loader for API access
	ebpfLoader *ebpf.Loader

	// Previous counter values for calculating deltas
	prevUplinkPackets   uint64
	prevDownlinkPackets uint64
	prevUplinkBytes     uint64
	prevDownlinkBytes   uint64
)

// DropEventJSON is the JSON representation of a drop event
type DropEventJSON struct {
	Timestamp string `json:"timestamp"`
	TEID      string `json:"teid"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   uint16 `json:"src_port"`
	DstPort   uint16 `json:"dst_port"`
	PktLen    uint32 `json:"pkt_len"`
	Reason    string `json:"reason"`
	Direction string `json:"direction"`
}

// SessionJSON is the JSON representation of a session (extended)
type SessionJSON struct {
	SEID      string   `json:"seid"`
	UEIP      string   `json:"ue_ip"`
	TEIDs     []string `json:"teids"`
	TEIDUL    string   `json:"teid_ul,omitempty"` // Uplink TEID (gNB -> UPF)
	TEIDDL    string   `json:"teid_dl,omitempty"` // Downlink TEID (UPF -> gNB)
	CreatedAt string   `json:"created_at"`
	PacketsUL uint64   `json:"packets_ul"`
	PacketsDL uint64   `json:"packets_dl"`

	// Extended fields
	UPFIP       string `json:"upf_ip,omitempty"`
	GNBIP       string `json:"gnb_ip,omitempty"`
	UplinkPeerIP string `json:"uplink_peer_ip,omitempty"`
	SUPI        string `json:"supi,omitempty"`
	DNN         string `json:"dnn,omitempty"`
	SNssai      string `json:"s_nssai,omitempty"`
	QFI         uint8  `json:"qfi,omitempty"`
	SessionType string `json:"session_type,omitempty"`
	SessionID   uint8  `json:"pdu_session_id,omitempty"`

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
	Duration   string `json:"duration"`
	LastActive string `json:"last_active,omitempty"`
}

func init() {
	prometheus.MustRegister(packetsTotal)
	prometheus.MustRegister(bytesTotal)
	prometheus.MustRegister(packetDropsTotal)
	prometheus.MustRegister(activeSessions)
}

func main() {
	flag.Parse()

	log.Println("============================================================")
	log.Println("    5G-DPOP: UPF Data Plane Observability Agent")
	log.Println("============================================================")

	// Check if running as root
	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root (for eBPF)")
	}

	// Initialize PFCP correlation
	pfcpCorrelation = pfcp.NewCorrelation()

	// Create eBPF loader
	loader := ebpf.NewLoader()

	// Set up event handler for drops
	loader.OnDropEvent = func(event ebpf.DropEvent) {
		reason := ebpf.FormatDropReason(event.Reason)
		direction := ebpf.FormatDirection(event.Direction)

		log.Printf("[DROP] reason=%s direction=%s teid=0x%x src=%s dst=%s len=%d",
			reason, direction,
			event.TEID,
			ebpf.FormatIP(event.SrcIP),
			ebpf.FormatIP(event.DstIP),
			event.PktLen)

		// Update Prometheus metrics
		packetDropsTotal.WithLabelValues(reason, direction).Inc()

		// Store drop event for API
		dropEvent := DropEventJSON{
			Timestamp: time.Now().Format(time.RFC3339),
			TEID:      fmt.Sprintf("0x%x", event.TEID),
			SrcIP:     ebpf.FormatIP(event.SrcIP),
			DstIP:     ebpf.FormatIP(event.DstIP),
			SrcPort:   event.SrcPort,
			DstPort:   event.DstPort,
			PktLen:    event.PktLen,
			Reason:    reason,
			Direction: direction,
		}

		dropEventsMu.Lock()
		recentDrops = append([]DropEventJSON{dropEvent}, recentDrops...)
		if len(recentDrops) > 100 {
			recentDrops = recentDrops[:100]
		}
		totalDrops++
		dropsByReason[reason]++
		dropEventsMu.Unlock()
	}

	// Load eBPF programs
	log.Println("Loading eBPF programs...")
	if err := loader.Load(); err != nil {
		log.Fatalf("Failed to load eBPF programs: %v", err)
	}
	defer loader.Close()

	// Enable detailed tracing for topology discovery
	if err := loader.EnableDetailedTracing(true); err != nil {
		log.Printf("[WARN] Failed to enable detailed tracing: %v", err)
	} else {
		log.Println("[INFO] Detailed tracing enabled for topology discovery")
	}

	// Set up packet event handler
	loader.OnPacketEvent = func(event ebpf.PacketEvent) {
		// Only interested in Uplink packets to discover Uplink Peer (gNB or prev UPF)
		if event.Direction == ebpf.DirectionUplink && event.TEID > 0 {
			// Convert uint32 IP to net.IP
			srcIP := net.IPv4(byte(event.SrcIP), byte(event.SrcIP>>8), byte(event.SrcIP>>16), byte(event.SrcIP>>24))
			
			// Update session with Uplink Peer IP
			pfcpCorrelation.UpdateUplinkPeer(event.TEID, srcIP)
		}
	}

	// Store loader globally for API access
	ebpfLoader = loader

	log.Println("[OK] eBPF programs loaded successfully")

	// NOTE: kfree_skb tracing is DISABLED by default because it captures ALL kernel drops
	// which creates too much noise. Only gtp5g-specific drops are captured via kprobes.
	// To enable kernel-wide drop tracing, use: POST /api/config/drop-tracing {"enabled": true}
	log.Println("[INFO] Kernel-wide drop tracing (kfree_skb) is DISABLED by default")
	log.Println("[INFO] Only GTP/UPF specific drops will be captured via kprobes")

	// Start PFCP sniffer
	pfcpSniffer := pfcp.NewSniffer(*pfcpIface, 8805, pfcpCorrelation)
	if err := pfcpSniffer.Start(); err != nil {
		log.Printf("[WARN] Failed to start PFCP sniffer: %v", err)
		log.Printf("       PDU session tracking will be limited")
	} else {
		defer pfcpSniffer.Stop()
		log.Printf("[OK] PFCP sniffer started on interface %s", *pfcpIface)
	}

	// Start event processing loop
	loader.StartEventLoop()
	log.Println("[OK] Event loop started")

	// Start Prometheus HTTP server with additional API endpoints
	go startHTTPServer()

	// Start periodic stats collection
	go collectStats(loader)

	// Start periodic session count update
	go updateSessionCount()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Println("[INFO] Agent is running. Press Ctrl+C to stop.")
	log.Println("   Metrics available at http://localhost:9100/metrics")
	log.Println("   Sessions API: http://localhost:9100/api/sessions")
	log.Println("   Drops API: http://localhost:9100/api/drops")
	log.Println("")

	<-sigChan
	log.Println("\n[INFO] Shutting down...")
}

func startHTTPServer() {
	// Prometheus metrics
	http.Handle("/metrics", promhttp.Handler())

	// Health check
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Drop events API
	http.HandleFunc("/api/drops", handleDropsAPI)

	// Sessions API
	http.HandleFunc("/api/sessions", handleSessionsAPI)

	// Demo API - inject test data for development
	http.HandleFunc("/api/demo/inject-drop", handleDemoInjectDrop)
	http.HandleFunc("/api/demo/inject-session", handleDemoInjectSession)

	// Sync API - sync sessions from free5GC logs
	http.HandleFunc("/api/sync/sessions", handleSyncSessions)

	// Drop tracing control API
	http.HandleFunc("/api/config/drop-tracing", handleDropTracingConfig)

	log.Println("[INFO] HTTP server listening on :9100")
	if err := http.ListenAndServe(":9100", nil); err != nil {
		log.Printf("HTTP server error: %v", err)
	}
}

func handleDropsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	dropEventsMu.RLock()
	defer dropEventsMu.RUnlock()

	// Calculate drop rate
	var dropRate float64
	totalPackets := prevUplinkPackets + prevDownlinkPackets
	if totalPackets > 0 {
		dropRate = float64(totalDrops) / float64(totalPackets) * 100
	}

	response := map[string]interface{}{
		"total":        totalDrops,
		"rate_percent": dropRate,
		"recent_drops": recentDrops,
		"by_reason":    dropsByReason,
	}

	json.NewEncoder(w).Encode(response)
}

func handleSessionsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	sessions := pfcpCorrelation.GetAllSessions()

	sessionList := make([]SessionJSON, 0, len(sessions))
	for _, s := range sessions {
		teids := make([]string, 0, len(s.TEIDs))
		for _, teid := range s.TEIDs {
			teids = append(teids, fmt.Sprintf("0x%x", teid))
		}

		// Extract UL/DL TEIDs (convention: first is UL, second is DL)
		teidUL := ""
		teidDL := ""
		if len(s.TEIDs) >= 1 {
			teidUL = fmt.Sprintf("0x%x", s.TEIDs[0])
		}
		if len(s.TEIDs) >= 2 {
			teidDL = fmt.Sprintf("0x%x", s.TEIDs[1])
		}

		ueIP := "N/A"
		if s.UEIP != nil {
			ueIP = s.UEIP.String()
		}

		upfIP := ""
		if s.UPFIP != nil {
			upfIP = s.UPFIP.String()
		}

		gnbIP := ""
		if s.GNBIP != nil {
			gnbIP = s.GNBIP.String()
		}

		uplinkPeerIP := ""
		if s.UplinkPeerIP != nil {
			uplinkPeerIP = s.UplinkPeerIP.String()
		}

		// Calculate duration
		duration := time.Since(s.CreatedAt)
		durationStr := formatDuration(duration)

		// Determine status
		status := "Active"
		if s.Status != "" {
			status = s.Status
		}

		lastActive := ""
		if !s.LastActive.IsZero() {
			lastActive = s.LastActive.Format(time.RFC3339)
		}

		sessionList = append(sessionList, SessionJSON{
			SEID:      fmt.Sprintf("0x%x", s.SEID),
			UEIP:      ueIP,
			TEIDs:     teids,
			TEIDUL:    teidUL,
			TEIDDL:    teidDL,
			CreatedAt: s.CreatedAt.Format(time.RFC3339),
			PacketsUL: s.PacketsUL,
			PacketsDL: s.PacketsDL,

			// Extended fields
			UPFIP:       upfIP,
			GNBIP:       gnbIP,
			UplinkPeerIP: uplinkPeerIP,
			SUPI:        s.SUPI,
			DNN:         s.DNN,
			SNssai:      s.SNssai,
			QFI:         s.QFI,
			SessionType: s.SessionType,
			SessionID:   s.SessionID,

			// Traffic
			BytesUL: s.BytesUL,
			BytesDL: s.BytesDL,

			// QoS
			QoS5QI:      s.QoS5QI,
			ARPPL:       s.ARPPL,
			GBRUplink:   s.GBRUplink,
			GBRDownlink: s.GBRDownlink,
			MBRUplink:   s.MBRUplink,
			MBRDownlink: s.MBRDownlink,

			// Status
			Status:     status,
			Duration:   durationStr,
			LastActive: lastActive,
		})
	}

	response := map[string]interface{}{
		"total":    len(sessionList),
		"sessions": sessionList,
	}

	json.NewEncoder(w).Encode(response)
}

// handleDropTracingConfig handles enabling/disabling kernel drop tracing
func handleDropTracingConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method == "GET" {
		// Return current status
		json.NewEncoder(w).Encode(map[string]interface{}{
			"drop_tracing_enabled": true, // We enable it by default now
			"message":              "Kernel drop tracing (kfree_skb) is active",
		})
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Enabled = true // Default to enable
	}

	if ebpfLoader == nil {
		http.Error(w, "eBPF loader not initialized", http.StatusInternalServerError)
		return
	}

	if err := ebpfLoader.EnableDropTracing(req.Enabled); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": fmt.Sprintf("Failed to set drop tracing: %v", err),
		})
		return
	}

	state := "disabled"
	if req.Enabled {
		state = "enabled"
	}
	log.Printf("[CONFIG] Drop tracing %s", state)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"message": fmt.Sprintf("Drop tracing %s", state),
		"enabled": req.Enabled,
	})
}

// formatDuration formats a duration into a human-readable string
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	return fmt.Sprintf("%dd %dh", days, hours)
}

func updateSessionCount() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		count := pfcpCorrelation.SessionCount()
		activeSessions.Set(float64(count))
	}
}

func collectStats(loader *ebpf.Loader) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		uplink, downlink, err := loader.GetTrafficStats()
		if err != nil {
			log.Printf("Error getting stats: %v", err)
			continue
		}

		// Calculate deltas
		uplinkPktDelta := uplink.Packets - prevUplinkPackets
		downlinkPktDelta := downlink.Packets - prevDownlinkPackets
		uplinkBytesDelta := uplink.Bytes - prevUplinkBytes
		downlinkBytesDelta := downlink.Bytes - prevDownlinkBytes

		// Update previous values
		prevUplinkPackets = uplink.Packets
		prevDownlinkPackets = downlink.Packets
		prevUplinkBytes = uplink.Bytes
		prevDownlinkBytes = downlink.Bytes

		// Update Prometheus counters
		if uplinkPktDelta > 0 {
			packetsTotal.WithLabelValues("uplink").Add(float64(uplinkPktDelta))
			bytesTotal.WithLabelValues("uplink").Add(float64(uplinkBytesDelta))
		}
		if downlinkPktDelta > 0 {
			packetsTotal.WithLabelValues("downlink").Add(float64(downlinkPktDelta))
			bytesTotal.WithLabelValues("downlink").Add(float64(downlinkBytesDelta))
		}

		// Update per-session stats from eBPF TEID counters
		updateSessionStatsFromEBPF(loader)

		// Print stats if there's activity
		if uplinkPktDelta > 0 || downlinkPktDelta > 0 {
			fmt.Printf("\rUL: %d pkts (%s)  DL: %d pkts (%s)          ",
				uplink.Packets, formatBytes(uplink.Bytes),
				downlink.Packets, formatBytes(downlink.Bytes))
		}
	}
}

// updateSessionStatsFromEBPF syncs TEID stats from eBPF to session objects
func updateSessionStatsFromEBPF(loader *ebpf.Loader) {
	// Update uplink stats from TEID counters
	teidStats, err := loader.GetAllTEIDStats()
	if err == nil {
		for teid, stats := range teidStats {
			session, found := pfcpCorrelation.GetSessionByTEID(teid)
			if found && session != nil {
				// TEID stats are uplink traffic
				session.PacketsUL = stats.Packets
				session.BytesUL = stats.Bytes
				session.LastActive = time.Now()
			}
		}
	}

	// Update downlink stats from UE IP counters
	ueIPStats, err := loader.GetAllUEIPStats()
	if err == nil {
		for ueIPUint32, stats := range ueIPStats {
			// Convert uint32 to IP string
			ueIP := ebpf.FormatIP(ueIPUint32)
			session, found := pfcpCorrelation.GetSessionByUEIP(ueIP)
			if found && session != nil {
				// UE IP stats are downlink traffic
				session.PacketsDL = stats.Packets
				session.BytesDL = stats.Bytes
				session.LastActive = time.Now()
			}
		}
	}
}

func formatBytes(bytes uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// Demo API handlers for testing purposes

// handleDemoInjectDrop injects a test drop event
func handleDemoInjectDrop(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body or use defaults
	var req struct {
		Reason    string `json:"reason"`
		Direction string `json:"direction"`
		Count     int    `json:"count"`
	}
	req.Reason = "INVALID_TEID"
	req.Direction = "uplink"
	req.Count = 1

	json.NewDecoder(r.Body).Decode(&req)

	if req.Count <= 0 {
		req.Count = 1
	}
	if req.Count > 100 {
		req.Count = 100
	}

	// Realistic drop reasons with weighted probabilities
	// Based on real-world 5G UPF scenarios
	type dropReasonWeight struct {
		reason string
		weight int // Higher weight = more likely to occur
	}
	weightedReasons := []dropReasonWeight{
		// Common drops (high probability)
		{"INVALID_TEID", 25},  // Most common: stale sessions, race conditions
		{"NO_PDR_MATCH", 20},  // Common: configuration issues, timing
		{"NO_GTP_TUNNEL", 15}, // Common: session not fully established
		{"KERNEL_DROP", 10},   // Common: various kernel-level drops
		{"ROUTING_DROP", 8},   // Moderately common: routing issues

		// Less common drops
		{"TTL_EXPIRED", 5},   // Occasional: routing loops
		{"DECAP_FAILED", 4},  // Occasional: malformed packets
		{"ENCAP_FAILED", 4},  // Occasional: resource issues
		{"MALFORMED_GTP", 3}, // Rare: corrupted packets
		{"MTU_EXCEEDED", 3},  // Rare: jumbo frames without fragmentation

		// Rare drops (require specific conditions)
		{"QOS_VIOLATION", 1},   // Rare: needs QoS policy enforcement
		{"POLICY_DROP", 1},     // Rare: needs ACL rules
		{"NO_FAR_ACTION", 0},   // Very rare: incomplete configuration (disabled)
		{"BUFFER_OVERFLOW", 0}, // Very rare: extreme load (disabled)
		{"MEMORY_ERROR", 0},    // Very rare: system under pressure (disabled)
	}

	// Calculate total weight
	totalWeight := 0
	for _, wr := range weightedReasons {
		totalWeight += wr.weight
	}

	// Helper function to select weighted random reason
	selectWeightedReason := func() string {
		r := int(time.Now().UnixNano() % int64(totalWeight))
		cumulative := 0
		for _, wr := range weightedReasons {
			cumulative += wr.weight
			if r < cumulative {
				return wr.reason
			}
		}
		return "INVALID_TEID" // fallback
	}

	// Direction distribution: Uplink drops are slightly more common in real scenarios
	// (UE mobility, handover issues)
	selectDirection := func() string {
		if time.Now().UnixNano()%100 < 55 { // 55% uplink, 45% downlink
			return "uplink"
		}
		return "downlink"
	}

	// Realistic IP pools
	ueIPPool := "10.60.0." // UE IP pool (free5gc default)
	dnIPPools := []string{ // External destinations
		"8.8.8.",       // Google DNS
		"1.1.1.",       // Cloudflare
		"142.250.185.", // Google services
		"31.13.72.",    // Facebook
		"157.240.1.",   // Facebook
		"104.244.42.",  // Twitter
		"151.101.1.",   // Reddit/Fastly
	}

	for i := 0; i < req.Count; i++ {
		reason := req.Reason
		direction := req.Direction
		if reason == "random" || reason == "" {
			reason = selectWeightedReason()
		}
		if direction == "random" || direction == "" {
			direction = selectDirection()
		}

		// Generate realistic IPs based on direction
		var srcIP, dstIP string
		ueIP := fmt.Sprintf("%s%d", ueIPPool, 1+time.Now().UnixNano()%254)
		dnIP := fmt.Sprintf("%s%d", dnIPPools[time.Now().UnixNano()%int64(len(dnIPPools))], 1+time.Now().UnixNano()%254)

		if direction == "uplink" {
			srcIP = ueIP // UE -> DN
			dstIP = dnIP
		} else {
			srcIP = dnIP // DN -> UE
			dstIP = ueIP
		}

		// Generate realistic TEID (random 32-bit with some structure)
		// Real TEIDs are allocated by SMF, usually in a range per UPF
		teid := uint32(0x00000001 + time.Now().UnixNano()%0x0000FFFF)

		// Realistic port numbers
		var srcPort, dstPort uint16
		commonPorts := []uint16{80, 443, 8080, 53, 123, 5060, 3478}
		if direction == "uplink" {
			srcPort = uint16(49152 + time.Now().UnixNano()%16383) // Ephemeral port
			dstPort = commonPorts[time.Now().UnixNano()%int64(len(commonPorts))]
		} else {
			srcPort = commonPorts[time.Now().UnixNano()%int64(len(commonPorts))]
			dstPort = uint16(49152 + time.Now().UnixNano()%16383)
		}

		// Realistic packet sizes (based on common traffic patterns)
		// Small: DNS, SIP signaling; Medium: HTTP headers; Large: video streaming
		pktSizes := []uint32{64, 128, 256, 512, 576, 1024, 1280, 1400, 1460, 1500}
		pktLen := pktSizes[time.Now().UnixNano()%int64(len(pktSizes))]

		dropEvent := DropEventJSON{
			Timestamp: time.Now().Format(time.RFC3339),
			TEID:      fmt.Sprintf("0x%08x", teid),
			SrcIP:     srcIP,
			DstIP:     dstIP,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			PktLen:    pktLen,
			Reason:    reason,
			Direction: direction,
		}

		// Update metrics
		packetDropsTotal.WithLabelValues(reason, direction).Inc()

		// Store drop event
		dropEventsMu.Lock()
		recentDrops = append([]DropEventJSON{dropEvent}, recentDrops...)
		if len(recentDrops) > 100 {
			recentDrops = recentDrops[:100]
		}
		totalDrops++
		dropsByReason[reason]++
		dropEventsMu.Unlock()

		log.Printf("[DEMO DROP] reason=%s direction=%s teid=%s", reason, direction, dropEvent.TEID)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"message": fmt.Sprintf("Injected %d drop event(s)", req.Count),
	})
}

// handleDemoInjectSession injects a test session
func handleDemoInjectSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body - support both random and specific sessions
	var req struct {
		Count int `json:"count"`
		// For specific session injection
		SEID  string   `json:"seid"`
		UEIP  string   `json:"ue_ip"`
		TEIDs []string `json:"teids"`
		SUPI  string   `json:"supi"`
		// Extended session info
		DNN         string `json:"dnn"`
		SNssai      string `json:"s_nssai"`
		SessionType string `json:"session_type"`
		SessionID   uint8  `json:"pdu_session_id"`
		QoS5QI      uint8  `json:"qos_5qi"`
		UPFIP       string `json:"upf_ip"`
		GNBIP       string `json:"gnb_ip"`
	}
	req.Count = 1

	json.NewDecoder(r.Body).Decode(&req)

	// If specific session info provided, use it
	if req.SEID != "" || req.UEIP != "" {
		var seid uint64
		if len(req.SEID) > 2 && req.SEID[:2] == "0x" {
			fmt.Sscanf(req.SEID, "0x%x", &seid)
		} else if req.SEID != "" {
			fmt.Sscanf(req.SEID, "%d", &seid)
		} else {
			seid = uint64(0x1)
		}

		ueIP := net.ParseIP(req.UEIP)
		if ueIP == nil {
			ueIP = net.ParseIP("10.60.0.1")
		}

		teids := make([]uint32, 0)
		for _, teidStr := range req.TEIDs {
			var teid uint32
			if len(teidStr) > 2 && teidStr[:2] == "0x" {
				fmt.Sscanf(teidStr, "0x%x", &teid)
			} else {
				fmt.Sscanf(teidStr, "%d", &teid)
			}
			if teid > 0 {
				teids = append(teids, teid)
			}
		}
		if len(teids) == 0 {
			teids = []uint32{1, 2}
		}

		// Set defaults for extended fields
		dnn := req.DNN
		if dnn == "" {
			dnn = "internet"
		}
		sNssai := req.SNssai
		if sNssai == "" {
			sNssai = "SST:1, SD:010203"
		}
		sessionType := req.SessionType
		if sessionType == "" {
			sessionType = "IPv4"
		}
		qos5qi := req.QoS5QI
		if qos5qi == 0 {
			qos5qi = 9 // Default non-GBR
		}

		session := &pfcp.Session{
			SEID:        seid,
			UEIP:        ueIP,
			TEIDs:       teids,
			CreatedAt:   time.Now(),
			SUPI:        req.SUPI,
			DNN:         dnn,
			SNssai:      sNssai,
			SessionType: sessionType,
			SessionID:   req.SessionID,
			QoS5QI:      qos5qi,
			UPFIP:       net.ParseIP(req.UPFIP),
			GNBIP:       net.ParseIP(req.GNBIP),
			Status:      "Active",
			LastActive:  time.Now(),
			// Default QoS values for non-GBR
			MBRUplink:   100000, // 100 Mbps
			MBRDownlink: 100000,
		}

		pfcpCorrelation.AddSession(session)

		log.Printf("[INJECT SESSION] SEID=0x%x UEIP=%s TEIDs=%v SUPI=%s DNN=%s",
			seid, ueIP, teids, req.SUPI, dnn)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"message": "Injected specific session",
			"session": map[string]interface{}{
				"seid":         fmt.Sprintf("0x%x", seid),
				"ue_ip":        ueIP.String(),
				"teids":        teids,
				"supi":         req.SUPI,
				"dnn":          dnn,
				"s_nssai":      sNssai,
				"qos_5qi":      qos5qi,
				"session_type": sessionType,
			},
		})
		return
	}

	// Random session generation with realistic 5G data
	if req.Count <= 0 {
		req.Count = 1
	}
	if req.Count > 10 {
		req.Count = 10
	}

	dnns := []string{"internet", "ims", "mec", "iot"}
	slices := []string{"SST:1, SD:010203", "SST:1, SD:112233", "SST:2, SD:000001"}
	qos5qis := []uint8{5, 6, 7, 8, 9} // Common 5QI values

	for i := 0; i < req.Count; i++ {
		seid := uint64(0x100000 + time.Now().UnixNano()%0xFFFFFF)
		teid1 := uint32(0x1000 + time.Now().UnixNano()%0xFFFF)
		teid2 := uint32(0x2000 + time.Now().UnixNano()%0xFFFF)
		ueIP := net.ParseIP(fmt.Sprintf("10.60.0.%d", 1+i+int(time.Now().UnixNano())%254))

		session := &pfcp.Session{
			SEID:        seid,
			UEIP:        ueIP,
			UPFIP:       net.ParseIP("10.200.200.101"),
			GNBIP:       net.ParseIP("10.200.200.1"),
			TEIDs:       []uint32{teid1, teid2},
			CreatedAt:   time.Now(),
			SUPI:        fmt.Sprintf("imsi-20893000000000%d", 1+i),
			DNN:         dnns[time.Now().UnixNano()%int64(len(dnns))],
			SNssai:      slices[time.Now().UnixNano()%int64(len(slices))],
			SessionType: "IPv4",
			SessionID:   uint8(1 + i),
			QoS5QI:      qos5qis[time.Now().UnixNano()%int64(len(qos5qis))],
			Status:      "Active",
			LastActive:  time.Now(),
			MBRUplink:   100000,
			MBRDownlink: 100000,
			PacketsUL:   uint64(time.Now().UnixNano() % 10000),
			PacketsDL:   uint64(time.Now().UnixNano() % 10000),
			BytesUL:     uint64(time.Now().UnixNano() % 10000000),
			BytesDL:     uint64(time.Now().UnixNano() % 10000000),
		}

		pfcpCorrelation.AddSession(session)

		log.Printf("[DEMO SESSION] SEID=0x%x UEIP=%s TEIDs=[0x%x, 0x%x] DNN=%s",
			seid, session.UEIP, teid1, teid2, session.DNN)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"message": fmt.Sprintf("Injected %d session(s)", req.Count),
	})
}

// handleSyncSessions syncs sessions from free5GC logs or allows manual session creation
func handleSyncSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body for manual session creation
	var req struct {
		Sessions []struct {
			SEID  string   `json:"seid"`
			UEIP  string   `json:"ue_ip"`
			TEIDs []string `json:"teids"`
			SUPI  string   `json:"supi"`
		} `json:"sessions"`
		// Or auto-sync from free5GC log
		LogPath string `json:"log_path"`
	}

	json.NewDecoder(r.Body).Decode(&req)

	syncedCount := 0

	// If manual sessions provided
	if len(req.Sessions) > 0 {
		for _, s := range req.Sessions {
			// Parse SEID (hex string like "0x1" or decimal)
			var seid uint64
			if len(s.SEID) > 2 && s.SEID[:2] == "0x" {
				fmt.Sscanf(s.SEID, "0x%x", &seid)
			} else {
				fmt.Sscanf(s.SEID, "%d", &seid)
			}

			// Parse TEIDs
			teids := make([]uint32, 0)
			for _, teidStr := range s.TEIDs {
				var teid uint32
				if len(teidStr) > 2 && teidStr[:2] == "0x" {
					fmt.Sscanf(teidStr, "0x%x", &teid)
				} else {
					fmt.Sscanf(teidStr, "%d", &teid)
				}
				if teid > 0 {
					teids = append(teids, teid)
				}
			}

			session := &pfcp.Session{
				SEID:      seid,
				UEIP:      net.ParseIP(s.UEIP),
				TEIDs:     teids,
				CreatedAt: time.Now(),
			}

			pfcpCorrelation.AddSession(session)
			syncedCount++

			log.Printf("[SYNC] Session added: SEID=0x%x UEIP=%s TEIDs=%v SUPI=%s",
				seid, s.UEIP, teids, s.SUPI)
		}
	}

	// If log path provided, try to parse sessions from free5GC log
	if req.LogPath != "" {
		parsed, err := parseSessionsFromLog(req.LogPath)
		if err != nil {
			log.Printf("[SYNC] Failed to parse log: %v", err)
		} else {
			for _, session := range parsed {
				pfcpCorrelation.AddSession(session)
				syncedCount++
			}
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"message": fmt.Sprintf("Synced %d session(s)", syncedCount),
		"total":   pfcpCorrelation.SessionCount(),
	})
}

// parseSessionsFromLog attempts to parse session info from free5GC log
func parseSessionsFromLog(logPath string) ([]*pfcp.Session, error) {
	sessions := make([]*pfcp.Session, 0)

	// This is a simplified parser - in production, you'd want more robust parsing
	data, err := os.ReadFile(logPath)
	if err != nil {
		return nil, err
	}

	content := string(data)
	lines := strings.Split(content, "\n")

	// Track current session info being built
	var currentSEID uint64
	var currentUEIP net.IP

	for _, line := range lines {
		// Look for SEID assignments
		if strings.Contains(line, "UPSEID=") || strings.Contains(line, "CPSEID=") {
			// Extract SEID value (e.g., UPSEID="0x1")
			if idx := strings.Index(line, "UPSEID=\"0x"); idx >= 0 {
				var seid uint64
				fmt.Sscanf(line[idx+10:], "%x", &seid)
				if seid > 0 {
					currentSEID = seid
				}
			}
		}

		// Look for UE IP allocation
		if strings.Contains(line, "Allocated UE IP address:") || strings.Contains(line, "Allocated PDUAdress") {
			// Extract IP (e.g., "10.60.0.1")
			parts := strings.Fields(line)
			for _, part := range parts {
				if ip := net.ParseIP(strings.Trim(part, "[]\"'")); ip != nil && ip.To4() != nil {
					// Check if it looks like a UE IP (10.60.x.x or 10.61.x.x)
					if strings.HasPrefix(ip.String(), "10.60.") || strings.HasPrefix(ip.String(), "10.61.") {
						currentUEIP = ip
					}
				}
			}
		}

		// If we have both SEID and UE IP, create session
		if currentSEID > 0 && currentUEIP != nil {
			session := &pfcp.Session{
				SEID:      currentSEID,
				UEIP:      currentUEIP,
				TEIDs:     []uint32{uint32(currentSEID)}, // Use SEID as TEID placeholder
				CreatedAt: time.Now(),
			}
			sessions = append(sessions, session)
			log.Printf("[SYNC] Parsed session from log: SEID=0x%x UEIP=%s", currentSEID, currentUEIP)

			// Reset for next session
			currentSEID = 0
			currentUEIP = nil
		}
	}

	return sessions, nil
}
