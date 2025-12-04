package pfcp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PFCP Message Types (3GPP TS 29.244)
const (
	MsgTypeHeartbeatRequest             = 1
	MsgTypeHeartbeatResponse            = 2
	MsgTypeSessionEstablishmentRequest  = 50
	MsgTypeSessionEstablishmentResponse = 51
	MsgTypeSessionModificationRequest   = 52
	MsgTypeSessionModificationResponse  = 53
	MsgTypeSessionDeletionRequest       = 54
	MsgTypeSessionDeletionResponse      = 55
)

// PFCP IE Types (3GPP TS 29.244)
const (
	IETypeCreatePDR            = 1   // Create PDR
	IETypePDI                  = 2   // PDI (Packet Detection Information)
	IETypeCreateFAR            = 3   // Create FAR
	IETypeForwardingParameters = 4   // Forwarding Parameters
	IETypeCreateURR            = 6   // Create URR
	IETypeCreateQER            = 7   // Create QER
	IETypeSourceInterface      = 20  // Source Interface
	IETypeFTEID                = 21  // F-TEID
	IETypeNetworkInstance      = 22  // Network Instance (DNN)
	IETypeSDFFilter            = 23  // SDF Filter
	IETypeApplicationID        = 24  // Application ID
	IETypeGateStatus           = 25  // Gate Status
	IETypeMBR                  = 26  // MBR (Maximum Bit Rate)
	IETypeGBR                  = 27  // GBR (Guaranteed Bit Rate)
	IETypeQERCorrelationID     = 28  // QER Correlation ID
	IETypePrecedence           = 29  // Precedence
	IETypePDUSessionType       = 85  // PDU Session Type
	IETypeOuterHeaderRemoval   = 95  // Outer Header Removal
	IETypeOuterHeaderCreation  = 84  // Outer Header Creation
	IETypeUEIPAddr             = 93  // UE IP Address
	IETypeQFI                  = 124 // QFI (QoS Flow Identifier)
	IEType5QI                  = 45  // 5QI (5G QoS Identifier)
	IETypeARP                  = 46  // ARP (Allocation and Retention Priority)
	IETypeSNSSAI               = 148 // S-NSSAI (Network Slice Selection Assistance Information)
	IEType3GPPInterfaceType    = 160 // 3GPP Interface Type
)

// Session represents a PFCP session with its associated TEIDs
type Session struct {
	SEID       uint64
	LocalSEID  uint64
	RemoteSEID uint64
	UEIP       net.IP
	UPFIP      net.IP
	GNBIP      net.IP   // Downlink Peer IP (gNB or next UPF)
	UplinkPeerIP net.IP // Uplink Peer IP (gNB or prev UPF)
	TEIDs      []uint32 // Associated GTP TEIDs
	CreatedAt  time.Time
	ModifiedAt time.Time
	PDRCount   int
	FARCount   int

	// Extended session info
	SUPI        string // Subscriber Permanent ID (IMSI)
	DNN         string // Data Network Name (APN)
	SNssai      string // S-NSSAI (Network Slice)
	QFI         uint8  // QoS Flow Identifier
	SessionType string // IPv4, IPv6, IPv4v6
	SessionID   uint8  // PDU Session ID

	// Traffic statistics
	BytesUL   uint64
	BytesDL   uint64
	PacketsUL uint64
	PacketsDL uint64

	// QoS parameters
	QoS5QI      uint8  // 5G QoS Identifier
	ARPPL       uint8  // ARP Priority Level
	GBRUplink   uint64 // Guaranteed Bit Rate UL (kbps)
	GBRDownlink uint64 // Guaranteed Bit Rate DL (kbps)
	MBRUplink   uint64 // Maximum Bit Rate UL (kbps)
	MBRDownlink uint64 // Maximum Bit Rate DL (kbps)

	// Status
	Status     string // Active, Idle, Releasing
	LastActive time.Time
}

// Correlation manages the mapping between sessions and TEIDs
type Correlation struct {
	mu          sync.RWMutex
	sessions    map[uint64]*Session // SEID -> Session
	teidMap     map[uint32]uint64   // TEID -> SEID
	ueIPMap     map[string]uint64   // UE IP string -> primary SEID (for deduplication)
	seidCounter uint64              // Counter for generating unique SEIDs
	// Track session creation timestamps to handle race conditions
	sessionCreationTime map[string]time.Time // UE IP -> creation time
}

// NewCorrelation creates a new correlation store
func NewCorrelation() *Correlation {
	return &Correlation{
		sessions:            make(map[uint64]*Session),
		teidMap:             make(map[uint32]uint64),
		ueIPMap:             make(map[string]uint64),
		seidCounter:         0,
		sessionCreationTime: make(map[string]time.Time),
	}
}

// getNextSEID generates a sequential SEID for new sessions
// Uses atomic-like pattern with mutex already held by caller
func (c *Correlation) getNextSEID() uint64 {
	c.seidCounter++
	return c.seidCounter
}

// AddSession adds or updates a session
// Each unique UE IP should have exactly one session entry
// This function is thread-safe and handles concurrent session creation
func (c *Correlation) AddSession(session *Session) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If session has no UE IP, we cannot properly deduplicate - skip it
	if session.UEIP == nil {
		log.Printf("[WARN] AddSession: session without UE IP, skipping (SEID=0x%x)", session.SEID)
		return
	}

	ueIPStr := session.UEIP.String()

	// Check if we already have a session for this UE IP
	if existingSEID, exists := c.ueIPMap[ueIPStr]; exists {
		if existingSession, ok := c.sessions[existingSEID]; ok {
			// Only merge if this is clearly an update (same session being modified)
			// Don't merge if the existing session was just created (within 100ms)
			// This prevents race conditions during rapid session establishment
			creationTime, hasTime := c.sessionCreationTime[ueIPStr]
			timeSinceCreation := time.Since(creationTime)

			if hasTime && timeSinceCreation < 100*time.Millisecond {
				// Recent session - likely a race condition, skip this update
				log.Printf("[DEBUG] AddSession: Skipping duplicate for UE IP %s (created %v ago)",
					ueIPStr, timeSinceCreation)
				return
			}

			// Merge with existing session
			log.Printf("[DEBUG] AddSession: Merging session for UE IP %s (existing SEID=0x%x)",
				ueIPStr, existingSEID)

			// Merge TEIDs (avoid duplicates)
			teidSet := make(map[uint32]bool)
			for _, t := range existingSession.TEIDs {
				teidSet[t] = true
			}
			for _, t := range session.TEIDs {
				if !teidSet[t] && t != 0 {
					existingSession.TEIDs = append(existingSession.TEIDs, t)
					c.teidMap[t] = existingSEID
				}
			}
			// Update other fields if they have better data
			if session.DNN != "" && existingSession.DNN == "" {
				existingSession.DNN = session.DNN
			}
			if session.QFI != 0 && existingSession.QFI == 0 {
				existingSession.QFI = session.QFI
			}
			if session.UPFIP != nil && existingSession.UPFIP == nil {
				existingSession.UPFIP = session.UPFIP
			}
			if session.GNBIP != nil && existingSession.GNBIP == nil {
				existingSession.GNBIP = session.GNBIP
			}
			if session.MBRUplink > 0 {
				existingSession.MBRUplink = session.MBRUplink
			}
			if session.MBRDownlink > 0 {
				existingSession.MBRDownlink = session.MBRDownlink
			}
			existingSession.LastActive = time.Now()
			return
		}
	}

	// New session with this UE IP
	// Assign a new sequential SEID if not already set
	if session.SEID == 0 {
		session.SEID = c.getNextSEID()
	}

	// Register this UE IP -> SEID mapping
	c.ueIPMap[ueIPStr] = session.SEID
	c.sessionCreationTime[ueIPStr] = time.Now()

	// Store session
	c.sessions[session.SEID] = session
	for _, teid := range session.TEIDs {
		if teid != 0 {
			c.teidMap[teid] = session.SEID
		}
	}

	log.Printf("[DEBUG] AddSession: New session SEID=0x%x for UE IP %s (total sessions: %d)",
		session.SEID, ueIPStr, len(c.sessions))
}

// RemoveSession removes a session
func (c *Correlation) RemoveSession(seid uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if session, ok := c.sessions[seid]; ok {
		for _, teid := range session.TEIDs {
			delete(c.teidMap, teid)
		}
		// Remove from UE IP map and creation time tracking
		if session.UEIP != nil {
			ueIPStr := session.UEIP.String()
			delete(c.ueIPMap, ueIPStr)
			delete(c.sessionCreationTime, ueIPStr)
		}
		delete(c.sessions, seid)
		log.Printf("[DEBUG] RemoveSession: Removed SEID=0x%x (total sessions: %d)", seid, len(c.sessions))
	}
}

// GetSessionByTEID looks up session by TEID
func (c *Correlation) GetSessionByTEID(teid uint32) (*Session, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if seid, ok := c.teidMap[teid]; ok {
		return c.sessions[seid], true
	}
	return nil, false
}

// GetSessionBySEID looks up session by SEID
func (c *Correlation) GetSessionBySEID(seid uint64) (*Session, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	session, ok := c.sessions[seid]
	return session, ok
}

// GetSessionByUEIP looks up session by UE IP address
func (c *Correlation) GetSessionByUEIP(ueIP string) (*Session, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, session := range c.sessions {
		if session.UEIP != nil && session.UEIP.String() == ueIP {
			return session, true
		}
	}
	return nil, false
}

// GetAllSessions returns all sessions
func (c *Correlation) GetAllSessions() []*Session {
	c.mu.RLock()
	defer c.mu.RUnlock()

	sessions := make([]*Session, 0, len(c.sessions))
	for _, s := range c.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}

// SessionCount returns the number of active sessions
func (c *Correlation) SessionCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.sessions)
}

// Sniffer captures and parses PFCP packets
type Sniffer struct {
	handle      *pcap.Handle
	correlation *Correlation
	stopChan    chan struct{}
	iface       string
	port        uint16
}

// NewSniffer creates a new PFCP sniffer
func NewSniffer(iface string, port uint16, correlation *Correlation) *Sniffer {
	return &Sniffer{
		iface:       iface,
		port:        port,
		correlation: correlation,
		stopChan:    make(chan struct{}),
	}
}

// Start begins capturing PFCP packets
func (s *Sniffer) Start() error {
	var err error

	// Open the device for capturing
	s.handle, err = pcap.OpenLive(s.iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open device %s: %w", s.iface, err)
	}

	// Set BPF filter for PFCP (UDP port 8805)
	filter := fmt.Sprintf("udp port %d", s.port)
	if err := s.handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("failed to set BPF filter: %w", err)
	}

	log.Printf("PFCP Sniffer started on %s, filter: %s", s.iface, filter)

	go s.captureLoop()

	return nil
}

// Stop stops the sniffer
func (s *Sniffer) Stop() {
	close(s.stopChan)
	if s.handle != nil {
		s.handle.Close()
	}
}

func (s *Sniffer) captureLoop() {
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())

	for {
		select {
		case <-s.stopChan:
			return
		case packet := <-packetSource.Packets():
			s.processPacket(packet)
		}
	}
}

func (s *Sniffer) processPacket(packet gopacket.Packet) {
	// Get UDP layer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}

	udp, _ := udpLayer.(*layers.UDP)
	payload := udp.Payload

	if len(payload) < 8 {
		return
	}

	// Parse PFCP header (3GPP TS 29.244)
	// Byte 0: Version (3 bits) + Spare (3 bits) + MP (1 bit) + S (1 bit)
	// Byte 1: Message Type
	// Bytes 2-3: Message Length (excludes first 4 bytes of header)
	// If S=1: Bytes 4-11: SEID, then Bytes 12-15: Sequence Number + Spare
	// If S=0: Bytes 4-7: Sequence Number + Spare
	msgType := payload[1]
	msgLen := binary.BigEndian.Uint16(payload[2:4])

	// Check if it's a session message (has SEID) - S bit is bit 0
	hasSessionID := (payload[0] & 0x01) != 0

	var seid uint64
	var ieOffset int

	if hasSessionID {
		if len(payload) < 16 {
			return
		}
		seid = binary.BigEndian.Uint64(payload[4:12])
		ieOffset = 16 // Header (4) + SEID (8) + SeqNum (4) = 16
	} else {
		ieOffset = 8 // Header (4) + SeqNum (4) = 8
	}

	// Calculate IE data end position
	// msgLen is the length of everything after the first 4 bytes
	// So total packet should be: 4 + msgLen
	ieDataEnd := 4 + int(msgLen)
	if ieDataEnd > len(payload) {
		log.Printf("[PFCP-WARN] Message length (%d) exceeds payload (%d), truncating", ieDataEnd, len(payload))
		ieDataEnd = len(payload)
	}

	// Ensure we have IE data to process
	if ieOffset >= ieDataEnd {
		log.Printf("[PFCP-WARN] No IE data in message (offset=%d, end=%d)", ieOffset, ieDataEnd)
		return
	}

	ieData := payload[ieOffset:ieDataEnd]

	// Process based on message type
	// Only create sessions from Establishment Request (has complete data)
	// Response and Modification only update existing sessions
	switch msgType {
	case MsgTypeSessionEstablishmentRequest:
		log.Printf("[PFCP-DEBUG] Session Establishment Request: SEID=0x%x, msgLen=%d, ieDataLen=%d", seid, msgLen, len(ieData))
		s.handleSessionEstablishmentRequest(ieData)
	case MsgTypeSessionEstablishmentResponse:
		// Response contains the UPF-assigned SEID, but limited data
		// We'll update existing session if we can match by F-TEID
		log.Printf("[PFCP-DEBUG] Session Establishment Response: SEID=0x%x (ignored - use Request data)", seid)
	case MsgTypeSessionModificationRequest:
		log.Printf("[PFCP-DEBUG] Session Modification Request: SEID=0x%x", seid)
		s.handleSessionModification(seid, ieData)
	case MsgTypeSessionModificationResponse:
		log.Printf("[PFCP-DEBUG] Session Modification Response: SEID=0x%x (ignored)", seid)
	case MsgTypeSessionDeletionRequest:
		log.Printf("[PFCP-DEBUG] Session Deletion Request: SEID=0x%x", seid)
		s.handleSessionDeletion(seid)
	default:
		// Log unknown message types for debugging
		if hasSessionID {
			log.Printf("[PFCP-DEBUG] Unknown msg type 0x%x with SEID=0x%x", msgType, seid)
		}
	}
}

// handleSessionEstablishmentRequest handles Session Establishment Request
// This is the only place where new sessions are created (Request has all the data)
func (s *Sniffer) handleSessionEstablishmentRequest(ieData []byte) {
	// First, extract UE IP - this is our primary key for session identification
	ueIP := s.extractUEIP(ieData)
	if ueIP == nil {
		log.Printf("[PFCP] Session Establishment: No UE IP found in IEs, skipping")
		return
	}

	ueIPStr := ueIP.String()
	log.Printf("[PFCP] Session Establishment Request: UE_IP=%s", ueIPStr)

	// Extract TEIDs first - we need these to properly identify the session
	teids := s.extractUniqueTEIDs(ieData, nil)
	if len(teids) == 0 {
		log.Printf("   └─ Warning: No TEIDs found for UE IP %s", ueIPStr)
	}

	// Create new session - always create a new entry for each unique UE IP
	// The AddSession function will handle deduplication properly
	session := &Session{
		SEID:       0, // Will be assigned by AddSession
		UEIP:       ueIP,
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
		TEIDs:      teids,
		Status:     "Active",
	}

	// Parse IEs to extract all available info
	s.extractSessionInfo(ieData, session)

	// Extract F-TEID details (UPF/gNB IPs)
	s.extractFTEIDDetails(ieData, session)

	// Add session (will handle deduplication and SEID assignment)
	s.correlation.AddSession(session)

	log.Printf("   └─ Session created: TEIDs: %v, UE_IP: %v, DNN: %s, QFI: %d, MBR: UL=%d/DL=%d kbps",
		session.TEIDs, ueIP, session.DNN, session.QFI, session.MBRUplink, session.MBRDownlink)
}

func (s *Sniffer) handleSessionModification(seid uint64, ieData []byte) {
	log.Printf("[PFCP] Session Modification: SEID=0x%x", seid)

	// First try to find session by UE IP (our primary key)
	ueIP := s.extractUEIP(ieData)
	var session *Session
	var ok bool

	if ueIP != nil {
		session, ok = s.correlation.GetSessionByUEIP(ueIP.String())
		if ok {
			log.Printf("   └─ Found session by UE IP %s (SEID=0x%x)", ueIP.String(), session.SEID)
		}
	}

	// If not found by UE IP, try by SEID (fallback)
	if !ok {
		session, ok = s.correlation.GetSessionBySEID(seid)
		if ok {
			log.Printf("   └─ Found session by SEID 0x%x", seid)
		}
	}

	if !ok {
		// Session not found - only create if we have UE IP
		if ueIP == nil {
			log.Printf("   └─ Session not found and no UE IP, skipping modification")
			return
		}

		log.Printf("   └─ Session not found, creating from modification data with UE IP %s", ueIP.String())

		// Create new session - SEID will be assigned by AddSession
		session = &Session{
			SEID:       0, // Will be assigned by AddSession
			UEIP:       ueIP,
			CreatedAt:  time.Now(),
			LastActive: time.Now(),
			TEIDs:      make([]uint32, 0),
			Status:     "Active",
		}
	}

	// Extract session info from modification IEs
	s.extractSessionInfo(ieData, session)

	// Extract TEIDs and merge with existing (removes duplicates)
	session.TEIDs = s.extractUniqueTEIDs(ieData, session.TEIDs)

	// Extract UE IP if present and not already set
	if session.UEIP == nil && ueIP != nil {
		session.UEIP = ueIP
	}

	// Extract gNB IP from Modification (this is where gNB endpoint info appears)
	s.extractGNBIPFromModification(ieData, session)

	session.ModifiedAt = time.Now()
	session.LastActive = time.Now()
	s.correlation.AddSession(session)

	log.Printf("   └─ Updated: TEIDs: %v, UE_IP: %v, MBR: UL=%d/DL=%d kbps",
		session.TEIDs, session.UEIP, session.MBRUplink, session.MBRDownlink)
}

func (s *Sniffer) handleSessionDeletion(seid uint64) {
	log.Printf("PFCP Session Deletion: SEID=0x%x", seid)
	// Try to find session by the incoming SEID first
	if _, ok := s.correlation.GetSessionBySEID(seid); ok {
		s.correlation.RemoveSession(seid)
		log.Printf("   └─ Removed session by SEID 0x%x", seid)
	} else {
		// Session may have been stored with a different SEID (our sequential one)
		// This is expected since free5gc's SEID != our internal SEID
		log.Printf("   └─ Session SEID 0x%x not found in our store (this is normal)", seid)
	}
}

// extractSessionInfo extracts DNN, QFI, and other session info from PFCP IEs
func (s *Sniffer) extractSessionInfo(ieData []byte, session *Session) {
	s.parseIEsRecursive(ieData, func(ieType uint16, ieValue []byte) {
		switch ieType {
		case IETypeNetworkInstance: // Network Instance (DNN)
			if len(ieValue) > 0 {
				// DNN is encoded as a string (may have length prefix)
				dnn := string(ieValue)
				// Clean up the DNN string
				if len(dnn) > 0 && dnn[0] < 32 {
					// Has length prefix, skip it
					if len(ieValue) > 1 {
						dnn = string(ieValue[1:])
					}
				}
				if len(dnn) > 0 {
					session.DNN = dnn
					log.Printf("   └─ Found DNN: %s", dnn)
				}
			}
		case IETypeQFI: // QFI
			if len(ieValue) >= 1 {
				session.QFI = ieValue[0] & 0x3F // QFI is 6 bits
				log.Printf("   └─ Found QFI: %d", session.QFI)
			}
		case IETypeMBR: // Maximum Bit Rate (Type 26)
			// According to 3GPP TS 29.244, MBR IE format:
			// - UL MBR: 5 bytes (40 bits) in kbps
			// - DL MBR: 5 bytes (40 bits) in kbps
			// Total: 10 bytes
			log.Printf("   └─ MBR IE length: %d bytes, content: %x", len(ieValue), ieValue)
			if len(ieValue) >= 10 {
				// 5 bytes each: use 40-bit encoding
				ulMBR := uint64(0)
				dlMBR := uint64(0)
				for i := 0; i < 5; i++ {
					ulMBR = (ulMBR << 8) | uint64(ieValue[i])
					dlMBR = (dlMBR << 8) | uint64(ieValue[5+i])
				}
				session.MBRUplink = ulMBR
				session.MBRDownlink = dlMBR
				log.Printf("   └─ Found MBR (10-byte): UL=%d kbps, DL=%d kbps", session.MBRUplink, session.MBRDownlink)
			} else if len(ieValue) >= 8 {
				// Fallback: 4 bytes each (32-bit)
				session.MBRUplink = uint64(binary.BigEndian.Uint32(ieValue[0:4]))
				session.MBRDownlink = uint64(binary.BigEndian.Uint32(ieValue[4:8]))
				log.Printf("   └─ Found MBR (8-byte): UL=%d kbps, DL=%d kbps", session.MBRUplink, session.MBRDownlink)
			} else if len(ieValue) >= 4 {
				// Single direction (uplink only or downlink only)
				// This seems to be the case in current SMF implementation
				session.MBRUplink = uint64(binary.BigEndian.Uint32(ieValue[0:4]))
				log.Printf("   └─ Found MBR (4-byte, UL only): UL=%d kbps", session.MBRUplink)
			}
		case IETypeGBR: // Guaranteed Bit Rate
			if len(ieValue) >= 8 {
				session.GBRUplink = uint64(binary.BigEndian.Uint32(ieValue[0:4]))
				session.GBRDownlink = uint64(binary.BigEndian.Uint32(ieValue[4:8]))
				log.Printf("   └─ Found GBR: UL=%d kbps, DL=%d kbps", session.GBRUplink, session.GBRDownlink)
			}
		case IETypePrecedence: // Precedence (can indicate QoS priority)
			if len(ieValue) >= 4 {
				precedence := binary.BigEndian.Uint32(ieValue[0:4])
				log.Printf("   └─ Found Precedence: %d", precedence)
			}
		case IETypePDUSessionType: // PDU Session Type
			if len(ieValue) >= 1 {
				pduType := ieValue[0] & 0x07 // Lower 3 bits
				switch pduType {
				case 1:
					session.SessionType = "IPv4"
				case 2:
					session.SessionType = "IPv6"
				case 3:
					session.SessionType = "IPv4v6"
				case 4:
					session.SessionType = "Unstructured"
				case 5:
					session.SessionType = "Ethernet"
				default:
					session.SessionType = fmt.Sprintf("Type-%d", pduType)
				}
				log.Printf("   └─ Found PDU Session Type: %s", session.SessionType)
			}
		case IEType5QI: // 5QI (5G QoS Identifier)
			if len(ieValue) >= 1 {
				session.QoS5QI = ieValue[0]
				log.Printf("   └─ Found 5QI: %d", session.QoS5QI)
			}
		case IETypeARP: // ARP (Allocation and Retention Priority)
			if len(ieValue) >= 1 {
				// ARP IE format: Priority Level (4 bits) + PCI (1 bit) + PVI (1 bit) + spare (2 bits)
				session.ARPPL = (ieValue[0] >> 4) & 0x0F // Upper 4 bits are priority level
				log.Printf("   └─ Found ARP Priority Level: %d", session.ARPPL)
			}
		case IETypeSNSSAI: // S-NSSAI
			if len(ieValue) >= 1 {
				sst := ieValue[0]
				sd := ""
				if len(ieValue) >= 4 {
					// SD is 3 bytes (24 bits)
					sdVal := uint32(ieValue[1])<<16 | uint32(ieValue[2])<<8 | uint32(ieValue[3])
					if sdVal != 0xFFFFFF { // 0xFFFFFF means SD is not present
						sd = fmt.Sprintf("%06X", sdVal)
					}
				}
				session.SNssai = fmt.Sprintf("SST:%d", sst)
				if sd != "" {
					session.SNssai += fmt.Sprintf(",SD:%s", sd)
				}
				log.Printf("   └─ Found S-NSSAI: %s", session.SNssai)
			}
		}
	})
}

// extractFTEIDDetails extracts F-TEID IP addresses from Session Establishment
// Only extracts UPF IP from F-TEID (gNB IP comes from Modification)
func (s *Sniffer) extractFTEIDDetails(ieData []byte, session *Session) {
	s.parseIEsRecursive(ieData, func(ieType uint16, ieValue []byte) {
		if ieType == IETypeFTEID && len(ieValue) >= 5 {
			flags := ieValue[0]
			offset := 5 // Skip flags (1) + TEID (4)

			// Check for IPv4 address (bit 0)
			if flags&0x01 != 0 && len(ieValue) >= offset+4 {
				ip := net.IP(ieValue[offset : offset+4])
				// In Session Establishment, F-TEID contains UPF's N3 interface IP
				if session.UPFIP == nil {
					session.UPFIP = ip
					log.Printf("   └─ F-TEID UPF IP: %s", ip)
				}
			}
		}
		// Note: We don't extract gNB IP from Outer Header Creation in Establishment
		// because it may point to N6 (DN) direction, not N3 (gNB)
	})
}

// extractGNBIPFromModification extracts gNB IP from Session Modification
// This is where gNB's F-TEID info is provided after gNB responds to AMF
func (s *Sniffer) extractGNBIPFromModification(ieData []byte, session *Session) {
	s.parseIEsRecursive(ieData, func(ieType uint16, ieValue []byte) {
		// Outer Header Creation in Session Modification contains gNB endpoint
		// This is in FAR (Forwarding Action Rules) for downlink
		if ieType == IETypeOuterHeaderCreation && len(ieValue) >= 10 {
			// Flags (2) + TEID (4) + IPv4 (4)
			ip := net.IP(ieValue[6:10])
			// Only update gNB IP if it's different from UPF IP
			if session.UPFIP == nil || !ip.Equal(session.UPFIP) {
				session.GNBIP = ip
				log.Printf("   └─ Outer Header gNB IP: %s", ip)
			}
		}
		// Also check F-TEID in Update FAR which may contain gNB info
		if ieType == IETypeFTEID && len(ieValue) >= 5 {
			flags := ieValue[0]
			offset := 5 // Skip flags (1) + TEID (4)

			// Check for IPv4 address (bit 0)
			if flags&0x01 != 0 && len(ieValue) >= offset+4 {
				ip := net.IP(ieValue[offset : offset+4])
				// If this IP is different from UPF IP, it's likely gNB IP
				if session.UPFIP != nil && !ip.Equal(session.UPFIP) {
					session.GNBIP = ip
					log.Printf("   └─ F-TEID gNB IP from Modification: %s", ip)
				}
			}
		}
	})
}

// extractTEIDs extracts all F-TEIDs from PFCP IEs (including nested IEs)
func (s *Sniffer) extractTEIDs(ieData []byte) []uint32 {
	teids := make([]uint32, 0)
	s.parseIEsRecursive(ieData, func(ieType uint16, ieValue []byte) {
		// F-TEID IE (Type 21)
		if ieType == IETypeFTEID && len(ieValue) >= 5 {
			// First byte is flags, next 4 bytes is TEID
			teid := binary.BigEndian.Uint32(ieValue[1:5])
			if teid > 0 {
				teids = append(teids, teid)
				log.Printf("   └─ Found F-TEID: 0x%x", teid)
			}
		}
		// Outer Header Creation IE (Type 84) - contains TEID for downlink
		if ieType == 84 && len(ieValue) >= 6 {
			// Flags (2 bytes) + TEID (4 bytes)
			teid := binary.BigEndian.Uint32(ieValue[2:6])
			if teid > 0 {
				teids = append(teids, teid)
				log.Printf("   └─ Found Outer Header TEID: 0x%x", teid)
			}
		}
	})
	return teids
}

// extractUniqueTEIDs extracts TEIDs and merges with existing ones, removing duplicates
func (s *Sniffer) extractUniqueTEIDs(ieData []byte, existingTEIDs []uint32) []uint32 {
	// Use a map to track unique TEIDs
	teidSet := make(map[uint32]bool)

	// Add existing TEIDs to the set
	for _, t := range existingTEIDs {
		if t != 0 {
			teidSet[t] = true
		}
	}

	// Extract new TEIDs from IE data
	newTEIDs := s.extractTEIDs(ieData)
	for _, t := range newTEIDs {
		if t != 0 {
			teidSet[t] = true
		}
	}

	// Convert set back to slice
	result := make([]uint32, 0, len(teidSet))
	for t := range teidSet {
		result = append(result, t)
	}

	return result
}

// extractUEIP extracts UE IP Address from PFCP IEs (including nested IEs)
// According to 3GPP TS 29.244, UE IP Address IE (Type 93) format:
// - Flags (1 byte): bit 0=S/D, bit 1=V4, bit 2=V6, bit 3=IPv6D, bit 4=CHV4, bit 5=CHV6
// - IPv4 address (4 bytes) if V4 bit is set and CHV4 is not set
// - IPv6 address (16 bytes) if V6 bit is set and CHV6 is not set
func (s *Sniffer) extractUEIP(ieData []byte) net.IP {
	var ueIP net.IP
	var foundCount int

	s.parseIEsRecursive(ieData, func(ieType uint16, ieValue []byte) {
		// UE IP Address IE (Type 93)
		if ieType == IETypeUEIPAddr && len(ieValue) >= 1 {
			flags := ieValue[0]
			offset := 1

			// Check V4 bit (bit 1) and ensure CHV4 (bit 4) is not set
			// CHV4 means "Choose IPv4 Address" - the IP hasn't been assigned yet
			hasV4 := (flags & 0x02) != 0
			isChooseV4 := (flags & 0x10) != 0

			if hasV4 && !isChooseV4 && len(ieValue) >= offset+4 {
				extractedIP := net.IP(make([]byte, 4))
				copy(extractedIP, ieValue[offset:offset+4])

				// Validate that it's a proper UE IP (not 0.0.0.0)
				if !extractedIP.Equal(net.IPv4zero) {
					// Only use the first valid UE IP found (avoid overwriting)
					if ueIP == nil {
						ueIP = extractedIP
						foundCount++
						log.Printf("   └─ Found UE IP: %s (flags=0x%02x)", ueIP, flags)
					} else if !ueIP.Equal(extractedIP) {
						// Log if we find a different UE IP (shouldn't happen in same session)
						log.Printf("   └─ Additional UE IP found (ignored): %s", extractedIP)
					}
				}
			} else if isChooseV4 {
				log.Printf("   └─ UE IP Address IE with CHV4 flag (IP not yet assigned)")
			}
		}
	})

	if ueIP == nil {
		log.Printf("   └─ No valid UE IP found in PFCP message")
	}

	return ueIP
}

// parseIEsRecursive recursively parses PFCP IEs and calls callback for each IE
func (s *Sniffer) parseIEsRecursive(ieData []byte, callback func(ieType uint16, ieValue []byte)) {
	offset := 0

	for offset < len(ieData)-4 {
		if offset+4 > len(ieData) {
			break
		}

		ieType := binary.BigEndian.Uint16(ieData[offset : offset+2])
		ieLen := binary.BigEndian.Uint16(ieData[offset+2 : offset+4])

		if ieLen == 0 || offset+4+int(ieLen) > len(ieData) {
			break
		}

		ieValue := ieData[offset+4 : offset+4+int(ieLen)]

		// Call callback for this IE
		callback(ieType, ieValue)

		// Recursively parse grouped IEs
		// These IE types contain nested IEs:
		// - Create PDR (1), Create FAR (3), Create URR (6), Create QER (7)
		// - PDI (2), Forwarding Parameters (4), Duplicating Parameters (5)
		// - Update PDR (9), Update FAR (10), etc.
		switch ieType {
		case 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16:
			// These are grouped IEs, parse recursively
			s.parseIEsRecursive(ieValue, callback)
		}

		offset += 4 + int(ieLen)
	}
}

// GetCorrelation returns the correlation store
func (s *Sniffer) GetCorrelation() *Correlation {
	return s.correlation
}

// UpdateUplinkPeer updates the uplink peer IP for a session
func (c *Correlation) UpdateUplinkPeer(teid uint32, peerIP net.IP) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if seid, ok := c.teidMap[teid]; ok {
		if session, ok := c.sessions[seid]; ok {
			if session.UplinkPeerIP == nil || !session.UplinkPeerIP.Equal(peerIP) {
				session.UplinkPeerIP = peerIP
				log.Printf("[PFCP] Updated Uplink Peer IP for SEID 0x%x: %s", session.SEID, peerIP)
			}
		}
	}
}