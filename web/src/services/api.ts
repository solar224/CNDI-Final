// API Types
export interface TrafficStats {
    uplink: DirectionStats
    downlink: DirectionStats
}

export interface DirectionStats {
    packets: number
    bytes: number
    throughput_mbps: number
    last_updated: string
}

export interface DropStats {
    total: number
    rate_percent: number
    recent_drops: DropEvent[]
    by_reason: Record<string, number>
}

export interface DropEvent {
    timestamp: string
    teid: string
    src_ip: string
    dst_ip: string
    src_port?: number
    dst_port?: number
    reason: string
    direction: string
    pkt_len: number
    // Extended session correlation info (populated by frontend from sessions data)
    session?: {
        seid?: string
        ue_ip?: string
        supi?: string
        dnn?: string
        gnb_ip?: string
        upf_ip?: string
        qfi?: number
        status?: string
    }
}

// Drop reason metadata for detailed explanations
export interface DropReasonInfo {
    code: string
    name: string
    description: string
    impact: string
    possibleCauses: string[]
    suggestedActions: string[]
    severity: 'critical' | 'warning' | 'info'
    layer: 'GTP' | 'PFCP' | 'Kernel' | 'QoS' | 'Routing'
}

// Complete drop reason database - Direct 1:1 mapping with gtp5g error codes
// These match exactly with gtp5g/src/gtpu/encap.c definitions (codes 1-17)
export const DROP_REASON_DATABASE: Record<string, DropReasonInfo> = {
    'PKT_DROPPED': {
        code: '1',
        name: 'Packet Dropped',
        description: 'Generic packet drop in gtp5g module. The packet was explicitly dropped during processing.',
        impact: 'Packet is dropped. Root cause needs further investigation based on context.',
        possibleCauses: [
            'Generic drop during packet processing',
            'Internal gtp5g decision to drop packet',
            'Packet failed validation checks',
            'Unknown internal error'
        ],
        suggestedActions: [
            'Check dmesg for gtp5g specific errors: dmesg | grep gtp5g',
            'Enable gtp5g debug logging if available',
            'Check packet capture for anomalies',
            'Review UPF configuration'
        ],
        severity: 'warning',
        layer: 'GTP'
    },
    'ECHO_RESP_CREATE': {
        code: '2',
        name: 'Echo Response Creation Failed',
        description: 'Failed to create GTP Echo Response message. This is part of GTP path management.',
        impact: 'GTP path health check may fail. Path management disrupted.',
        possibleCauses: [
            'Memory allocation failure for Echo Response',
            'Socket buffer allocation failed',
            'Internal gtp5g error',
            'Resource exhaustion'
        ],
        suggestedActions: [
            'Check system memory: free -h',
            'Monitor gtp5g module: dmesg | grep gtp5g',
            'Check GTP-U socket status',
            'Verify UDP port 2152 is operational'
        ],
        severity: 'warning',
        layer: 'GTP'
    },
    'NO_ROUTE': {
        code: '3',
        name: 'No Route',
        description: 'No routing entry found for the packet destination. Cannot forward the packet.',
        impact: 'Packet cannot reach destination. Complete connectivity failure for this flow.',
        possibleCauses: [
            'Missing route to destination network',
            'Routing table not configured properly',
            'Next hop unreachable',
            'Network namespace routing issue',
            'VRF misconfiguration'
        ],
        suggestedActions: [
            'Check routing table: ip route show',
            'Verify default gateway: ip route get <dst_ip>',
            'Check network namespace: ip netns exec <ns> ip route',
            'Verify UPF N6 interface configuration',
            'Check Data Network connectivity'
        ],
        severity: 'critical',
        layer: 'Routing'
    },
    'PULL_FAILED': {
        code: '4',
        name: 'SKB Pull Failed',
        description: 'Failed to pull/remove bytes from sk_buff header. Cannot parse packet data.',
        impact: 'Packet parsing failed. Packet is dropped.',
        possibleCauses: [
            'Packet too short (truncated)',
            'Corrupted packet length',
            'skb data pointer corruption',
            'Invalid packet structure'
        ],
        suggestedActions: [
            'Capture packets for analysis: tcpdump -i any port 2152 -w capture.pcap',
            'Check for MTU issues causing truncation',
            'Verify packet integrity',
            'Check network interface for errors: ethtool -S <iface>'
        ],
        severity: 'critical',
        layer: 'GTP'
    },
    'INVALID_EXT_HDR': {
        code: '5',
        name: 'Invalid Extension Header',
        description: 'GTP-U extension header is malformed or unsupported. Cannot process GTP packet.',
        impact: 'GTP packet dropped due to invalid extension header.',
        possibleCauses: [
            'Unsupported GTP extension header type',
            'Corrupted extension header',
            'gNB sending non-standard headers',
            'Protocol version mismatch',
            'Packet corruption in transit'
        ],
        suggestedActions: [
            'Capture and analyze GTP packets: tcpdump -i any port 2152',
            'Check gNB GTP-U implementation',
            'Verify GTP extension header support in gtp5g',
            'Update gtp5g module if needed',
            'Check for network errors causing corruption'
        ],
        severity: 'critical',
        layer: 'GTP'
    },
    'NO_PDR': {
        code: '6',
        name: 'No PDR Match',
        description: 'No Packet Detection Rule (PDR) found for this packet. UPF cannot determine how to handle it.',
        impact: 'Packet dropped. User may experience connection timeout or data loss.',
        possibleCauses: [
            'PDU Session not fully established',
            'PFCP Session Establishment incomplete',
            'SMF failed to create PDR in UPF',
            'Stale session - PDR already deleted',
            'Race condition during handover',
            'TEID not registered in any PDR'
        ],
        suggestedActions: [
            'Check SMF logs for PFCP errors',
            'Verify PDU Session state in AMF',
            'Check PFCP association: Review SMF-UPF messages',
            'List active PDRs in UPF',
            'Check gtp5g PDR table: cat /proc/gtp5g/*/pdr'
        ],
        severity: 'critical',
        layer: 'PFCP'
    },
    'GENERAL': {
        code: '7',
        name: 'General Error',
        description: 'Generic error in gtp5g module. Catch-all for unclassified errors.',
        impact: 'Packet dropped due to unspecified error.',
        possibleCauses: [
            'Unclassified internal error',
            'Resource allocation failure',
            'Unexpected packet state',
            'Module internal inconsistency'
        ],
        suggestedActions: [
            'Check dmesg for detailed errors: dmesg | tail -100',
            'Review gtp5g module logs',
            'Check system resources (CPU, memory)',
            'Consider reloading gtp5g module if persistent'
        ],
        severity: 'warning',
        layer: 'GTP'
    },
    'UL_GATE_CLOSED': {
        code: '8',
        name: 'Uplink Gate Closed',
        description: 'QoS Enforcement Rule (QER) has uplink gate set to CLOSED. Uplink traffic is blocked.',
        impact: 'All uplink traffic for this session is blocked by QoS policy.',
        possibleCauses: [
            'QER configured with UL gate=CLOSED',
            'Session suspended by network',
            'Charging-related suspension',
            'Policy decision to block UL traffic',
            'SMF/PCF policy update'
        ],
        suggestedActions: [
            'Check QER configuration in UPF',
            'Review SMF session policy',
            'Check PCF policy decisions',
            'Verify charging/billing status',
            'Check if intentional policy action'
        ],
        severity: 'warning',
        layer: 'QoS'
    },
    'DL_GATE_CLOSED': {
        code: '9',
        name: 'Downlink Gate Closed',
        description: 'QoS Enforcement Rule (QER) has downlink gate set to CLOSED. Downlink traffic is blocked.',
        impact: 'All downlink traffic for this session is blocked by QoS policy.',
        possibleCauses: [
            'QER configured with DL gate=CLOSED',
            'Session suspended by network',
            'Buffering mode enabled (waiting for paging)',
            'Policy decision to block DL traffic',
            'UE in idle mode, DL buffering active'
        ],
        suggestedActions: [
            'Check QER configuration in UPF',
            'Verify if UE is in idle mode',
            'Check if DL buffering is expected',
            'Review SMF/PCF policy',
            'Check paging procedure status'
        ],
        severity: 'warning',
        layer: 'QoS'
    },
    'PDR_NULL': {
        code: '10',
        name: 'PDR Pointer NULL',
        description: 'PDR pointer is NULL in processing path. Internal consistency error.',
        impact: 'Packet dropped due to internal error. Similar to NO_PDR.',
        possibleCauses: [
            'Race condition during PDR deletion',
            'Internal gtp5g state inconsistency',
            'PDR lookup returned but invalid',
            'Memory corruption'
        ],
        suggestedActions: [
            'Check for recent PFCP session modifications',
            'Review gtp5g module logs: dmesg | grep gtp5g',
            'Verify UPF stability',
            'Consider UPF restart if persistent'
        ],
        severity: 'critical',
        layer: 'PFCP'
    },
    'NO_F_TEID': {
        code: '11',
        name: 'No F-TEID',
        description: 'Fully Qualified TEID (F-TEID) not found. Cannot identify GTP tunnel endpoint.',
        impact: 'GTP tunnel lookup failed. Packet cannot be processed.',
        possibleCauses: [
            'TEID not registered in gtp5g',
            'PDU Session not fully established',
            'FAR missing outer header creation info',
            'PFCP Session Establishment incomplete',
            'Stale TEID reference'
        ],
        suggestedActions: [
            'Check gtp5g tunnel table: cat /proc/gtp5g/*/far',
            'Verify FAR has Outer Header Creation',
            'Check PFCP Session Establishment',
            'Review SMF logs for FAR creation',
            'Verify TEID allocation'
        ],
        severity: 'critical',
        layer: 'GTP'
    },
    'URR_REPORT_FAIL': {
        code: '12',
        name: 'URR Report Failed',
        description: 'Usage Reporting Rule (URR) report failed to send. Charging/usage data may be lost.',
        impact: 'Usage report not sent. May affect billing accuracy.',
        possibleCauses: [
            'PFCP association down',
            'SMF unreachable',
            'Report buffer full',
            'Netlink communication failure'
        ],
        suggestedActions: [
            'Check PFCP association status',
            'Verify SMF connectivity from UPF',
            'Check UPF report queue',
            'Review PFCP heartbeat status'
        ],
        severity: 'warning',
        layer: 'PFCP'
    },
    'RED_PACKET': {
        code: '13',
        name: 'RED Packet Drop',
        description: 'Packet dropped by Random Early Detection (RED) algorithm. QoS congestion control active.',
        impact: 'Packet dropped to prevent congestion. Normal QoS behavior under load.',
        possibleCauses: [
            'Queue approaching capacity',
            'Congestion control activated',
            'Traffic rate exceeding configured limits',
            'Token bucket exhausted',
            'MBR/GBR enforcement'
        ],
        suggestedActions: [
            'Check session QoS parameters (MBR/GBR)',
            'Review traffic load patterns',
            'Verify QER rate limiting settings',
            'Consider adjusting QoS parameters',
            'Check if higher bandwidth is needed'
        ],
        severity: 'info',
        layer: 'QoS'
    },
    'IP_XMIT_FAIL': {
        code: '14',
        name: 'IP Transmit Failed',
        description: 'Failed to transmit IP packet after GTP processing. Network transmission error.',
        impact: 'Packet not sent to destination. Network connectivity issue.',
        possibleCauses: [
            'Network interface down',
            'ARP resolution failed',
            'Output queue full',
            'MTU exceeded (needs fragmentation)',
            'Routing failure at IP layer'
        ],
        suggestedActions: [
            'Check network interface status: ip link show',
            'Verify ARP table: ip neigh show',
            'Check interface queue: tc -s qdisc show',
            'Review MTU settings',
            'Check for interface errors: ip -s link'
        ],
        severity: 'critical',
        layer: 'Routing'
    },
    'NOT_TPDU': {
        code: '15',
        name: 'Not T-PDU',
        description: 'GTP message type is not T-PDU (GTP-U user data). Only T-PDU messages carry user traffic.',
        impact: 'Non-data GTP message dropped in data path.',
        possibleCauses: [
            'GTP control message in data path',
            'Echo Request/Response misrouted',
            'Error Indication message',
            'Unsupported message type',
            'Protocol confusion'
        ],
        suggestedActions: [
            'Capture GTP packets to identify message type',
            'Verify GTP-C and GTP-U port separation',
            'Check gNB GTP implementation',
            'Review packet routing configuration'
        ],
        severity: 'warning',
        layer: 'GTP'
    },
    'PULL_HDR_FAIL': {
        code: '16',
        name: 'Header Pull Failed',
        description: 'Failed to pull GTP/IP header from packet. Similar to PULL_FAILED but header-specific.',
        impact: 'Cannot extract header. Packet dropped.',
        possibleCauses: [
            'Packet too short for expected header',
            'Header length mismatch',
            'Corrupted length fields',
            'Fragmented packet issues'
        ],
        suggestedActions: [
            'Capture packets for analysis',
            'Check for fragmentation issues',
            'Verify packet integrity',
            'Check MTU configuration'
        ],
        severity: 'critical',
        layer: 'GTP'
    },
    'NETIF_RX_FAIL': {
        code: '17',
        name: 'Netif RX Failed',
        description: 'netif_rx() call failed. Cannot deliver decapsulated packet to network stack.',
        impact: 'Uplink packet lost after decapsulation. UE upload fails.',
        possibleCauses: [
            'Network stack backlog full',
            'CPU softirq overloaded',
            'Memory pressure',
            'netif_rx queue overflow'
        ],
        suggestedActions: [
            'Check CPU softirq: cat /proc/softirqs',
            'Monitor netdev backlog: sysctl net.core.netdev_budget',
            'Check system load: top',
            'Increase backlog: sysctl -w net.core.netdev_max_backlog=<value>',
            'Check for packet storms'
        ],
        severity: 'critical',
        layer: 'Kernel'
    },
    'UNKNOWN': {
        code: '255',
        name: 'Unknown Error',
        description: 'Unknown or unclassified drop reason. Error code not recognized.',
        impact: 'Packet dropped for unknown reason.',
        possibleCauses: [
            'New error code not yet mapped',
            'gtp5g module version mismatch',
            'Corrupted error code',
            'Internal error'
        ],
        suggestedActions: [
            'Check gtp5g module version',
            'Review dmesg for errors',
            'Update 5G-DPOP if gtp5g was updated',
            'Report issue if persistent'
        ],
        severity: 'warning',
        layer: 'GTP'
    }
}

export interface SessionInfo {
    // 基本識別 (後端回傳字串格式)
    seid: string           // "0x1234" 格式
    ue_ip: string
    teids: string[]        // ["0x1a", "0x1b"] 格式
    teid_ul?: string       // Uplink TEID (gNB -> UPF) "0x1a" 格式
    teid_dl?: string       // Downlink TEID (UPF -> gNB) "0x1b" 格式
    created_at: string     // RFC3339 格式 "2025-11-29T16:22:12Z"

    // 封包統計
    packets_ul: number
    packets_dl: number
    bytes_ul: number
    bytes_dl: number

    // 5G 識別資訊
    supi?: string          // "imsi-208930000000001"
    dnn?: string           // "internet"
    s_nssai?: string       // "SST:1, SD:010203"
    qfi?: number           // QoS Flow ID
    session_type?: string  // "IPv4"
    pdu_session_id?: number

    // 網路節點 IP
    upf_ip?: string
    gnb_ip?: string

    // QoS 參數
    qos_5qi?: number       // 5QI 值
    arp_priority?: number
    gbr_ul_kbps?: number
    gbr_dl_kbps?: number
    mbr_ul_kbps?: number
    mbr_dl_kbps?: number

    // 狀態
    status: string
    duration?: string
    last_active?: string
}

export interface TopologyNode {
    id: string
    type: 'ue' | 'gnb' | 'upf' | 'dn'
    label: string
    ip?: string
}

export interface TopologyLink {
    source: string
    target: string
    type: 'n3' | 'n4' | 'n6' | 'n9'
    label?: string
}

export interface TopologyData {
    nodes: TopologyNode[]
    links: TopologyLink[]
}

// API Functions
const API_BASE = '/api/v1'

export async function fetchHealth(): Promise<{ status: string; timestamp: string }> {
    const response = await fetch(`${API_BASE}/health`)
    if (!response.ok) throw new Error('Health check failed')
    return response.json()
}

export async function fetchTrafficMetrics(): Promise<TrafficStats> {
    const response = await fetch(`${API_BASE}/metrics/traffic`)
    if (!response.ok) throw new Error('Failed to fetch traffic metrics')
    return response.json()
}

export async function fetchDropMetrics(): Promise<DropStats> {
    const response = await fetch(`${API_BASE}/metrics/drops`)
    if (!response.ok) throw new Error('Failed to fetch drop metrics')
    return response.json()
}

export async function fetchSessions(): Promise<{ total: number; sessions: SessionInfo[] }> {
    const response = await fetch(`${API_BASE}/sessions`)
    if (!response.ok) throw new Error('Failed to fetch sessions')
    return response.json()
}

export async function fetchTopology(): Promise<TopologyData> {
    const response = await fetch(`${API_BASE}/topology`)
    if (!response.ok) throw new Error('Failed to fetch topology')
    return response.json()
}

export async function injectFault(type: string, target: string, count: number): Promise<void> {
    const response = await fetch(`${API_BASE}/fault/inject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, target, count }),
    })
    if (!response.ok) throw new Error('Failed to inject fault')
}

// WebSocket connection helper
export function createMetricsWebSocket(
    onMessage: (data: any) => void,
    onError: (error: Event) => void,
    onClose: () => void
): WebSocket {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    // Use the same host - vite proxy will handle forwarding to API server
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws/metrics`)

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data)
            onMessage(data)
        } catch (e) {
            console.error('Failed to parse WebSocket message:', e)
        }
    }

    ws.onerror = onError
    ws.onclose = onClose

    return ws
}
