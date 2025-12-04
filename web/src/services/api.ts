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

// Complete drop reason database based on eBPF kernel module definitions
export const DROP_REASON_DATABASE: Record<string, DropReasonInfo> = {
    'NO_PDR_MATCH': {
        code: '0',
        name: 'No PDR Match',
        description: 'Packet Detection Rule (PDR) not found for this packet. The UPF cannot determine how to process the packet.',
        impact: 'Packet is dropped. User may experience connection timeout or data loss.',
        possibleCauses: [
            'PDU Session not fully established',
            'PFCP Session Establishment incomplete',
            'SMF failed to create PDR in UPF',
            'Stale session - PDR already deleted',
            'Race condition during handover',
            'Configuration mismatch between SMF and UPF'
        ],
        suggestedActions: [
            'Check SMF logs for PFCP errors',
            'Verify PDU Session state in AMF',
            'Check if UE registration is complete',
            'Review SMF-UPF PFCP association status',
            'Check gtp5g kernel module logs: dmesg | grep gtp5g'
        ],
        severity: 'critical',
        layer: 'PFCP'
    },
    'INVALID_TEID': {
        code: '1',
        name: 'Invalid TEID',
        description: 'Tunnel Endpoint Identifier (TEID) is unknown or no longer valid. The GTP tunnel cannot be found.',
        impact: 'GTP packets cannot be processed. Complete connection failure for affected UE.',
        possibleCauses: [
            'Session deleted but packets still in flight',
            'TEID not yet allocated by SMF',
            'gNB handover in progress - old TEID invalid',
            'UPF restart lost TEID mapping',
            'Malicious packet with fake TEID',
            'PFCP Session Modification failed'
        ],
        suggestedActions: [
            'Check if PDU Session is active',
            'Verify TEID allocation in SMF logs',
            'Check for recent handover events',
            'Verify UPF session table: look for SEID/TEID mappings',
            'Review gtp5g tunnel list: cat /proc/gtp5g/*/tunnel'
        ],
        severity: 'critical',
        layer: 'GTP'
    },
    'QOS_VIOLATION': {
        code: '2',
        name: 'QoS Violation',
        description: 'Packet exceeds QoS policy limits (MBR/GBR thresholds or QFI mismatch).',
        impact: 'Packet dropped to enforce QoS. May cause temporary throughput reduction.',
        possibleCauses: [
            'User exceeded Maximum Bit Rate (MBR)',
            'Traffic burst exceeds token bucket limit',
            'QFI mismatch between packet and QoS rule',
            'Congestion control activated',
            'Rate limiting policy enforced'
        ],
        suggestedActions: [
            'Check session QoS parameters (MBR/GBR)',
            'Review traffic patterns for the UE',
            'Verify QER (QoS Enforcement Rule) configuration',
            'Check if higher bandwidth subscription is needed',
            'Review QoS flow settings in SMF'
        ],
        severity: 'warning',
        layer: 'QoS'
    },
    'KERNEL_DROP': {
        code: '3',
        name: 'Kernel Drop',
        description: 'Generic kernel-level packet drop. This can occur at various stages of packet processing.',
        impact: 'Variable impact depending on the specific kernel drop point.',
        possibleCauses: [
            'Netfilter/iptables rule blocked packet',
            'Conntrack table full',
            'Socket buffer overflow',
            'Memory pressure',
            'Rate limiting by kernel',
            'Invalid packet checksum'
        ],
        suggestedActions: [
            'Check iptables rules: iptables -L -n -v',
            'Monitor conntrack: conntrack -L | wc -l',
            'Check system memory: free -h',
            'Review dmesg for kernel warnings',
            'Check network interface drops: ip -s link'
        ],
        severity: 'warning',
        layer: 'Kernel'
    },
    'NO_FAR_ACTION': {
        code: '4',
        name: 'No FAR Action',
        description: 'Forwarding Action Rule (FAR) not found or incomplete. UPF does not know where to forward the packet.',
        impact: 'Packet cannot be forwarded. Similar impact to NO_PDR_MATCH.',
        possibleCauses: [
            'FAR not yet created by SMF',
            'FAR deleted before packet arrival',
            'PFCP Session incomplete',
            'Configuration error in SMF policy'
        ],
        suggestedActions: [
            'Check SMF PFCP session state',
            'Verify FAR creation in SMF logs',
            'Review PFCP Session Establishment messages',
            'Check UPF session configuration'
        ],
        severity: 'critical',
        layer: 'PFCP'
    },
    'BUFFER_OVERFLOW': {
        code: '5',
        name: 'Buffer Overflow',
        description: 'Ring buffer or packet queue is full. System cannot process packets fast enough.',
        impact: 'Multiple packets dropped. May indicate system overload.',
        possibleCauses: [
            'High traffic load exceeding capacity',
            'CPU bottleneck on UPF',
            'Ring buffer size too small',
            'Slow downstream processing',
            'Memory allocation failures'
        ],
        suggestedActions: [
            'Monitor CPU usage on UPF server',
            'Consider scaling UPF horizontally',
            'Increase ring buffer size if possible',
            'Check for slow packet processing: perf top',
            'Review network interface queue length'
        ],
        severity: 'critical',
        layer: 'Kernel'
    },
    'TTL_EXPIRED': {
        code: '6',
        name: 'TTL Expired',
        description: 'IP Time-To-Live reached zero. Packet hopped through too many routers.',
        impact: 'Packet dropped. May indicate routing loop or misconfigured network.',
        possibleCauses: [
            'Routing loop in network',
            'Packet initially sent with low TTL',
            'Misconfigured static routes',
            'Traceroute or path discovery packet'
        ],
        suggestedActions: [
            'Check routing table: ip route show',
            'Trace the packet path: traceroute',
            'Look for routing loops in network',
            'Verify default gateway configuration'
        ],
        severity: 'warning',
        layer: 'Routing'
    },
    'MTU_EXCEEDED': {
        code: '7',
        name: 'MTU Exceeded',
        description: 'Packet size exceeds Maximum Transmission Unit. GTP encapsulation adds overhead.',
        impact: 'Large packets dropped. May affect applications sending large data chunks.',
        possibleCauses: [
            'Application sending jumbo frames',
            'Path MTU discovery failed',
            'GTP overhead not accounted for',
            'DF (Don\'t Fragment) bit set',
            'MTU mismatch between network segments'
        ],
        suggestedActions: [
            'Check interface MTU: ip link show',
            'Verify GTP tunnel MTU (typically 1400 for GTP-U)',
            'Enable Path MTU Discovery',
            'Configure proper MTU on UE/gNB',
            'Consider TCP MSS clamping'
        ],
        severity: 'warning',
        layer: 'GTP'
    },
    'MALFORMED_GTP': {
        code: '8',
        name: 'Malformed GTP Header',
        description: 'GTP-U packet header is corrupted or invalid. Cannot parse GTP protocol fields.',
        impact: 'Packet dropped. May indicate network corruption or attack.',
        possibleCauses: [
            'Packet corruption in transit',
            'Buggy gNB/UPF implementation',
            'Protocol version mismatch',
            'Malicious packet injection',
            'Hardware failure causing bit errors'
        ],
        suggestedActions: [
            'Capture packets for analysis: tcpdump -i any port 2152',
            'Check for network hardware issues',
            'Verify gNB software version',
            'Review GTP-U packet structure',
            'Check interface error counters: ethtool -S'
        ],
        severity: 'critical',
        layer: 'GTP'
    },
    'NO_GTP_TUNNEL': {
        code: '9',
        name: 'No GTP Tunnel',
        description: 'GTP tunnel does not exist in gtp5g kernel module. Tunnel endpoint not established.',
        impact: 'Cannot process GTP packets. Complete data path failure.',
        possibleCauses: [
            'PDU Session not established',
            'Tunnel deleted during UE mobility',
            'gtp5g module restart lost state',
            'PFCP FAR missing Outer Header Creation',
            'N3 interface not configured properly'
        ],
        suggestedActions: [
            'Check gtp5g tunnels: cat /proc/gtp5g/*/tunnel',
            'Verify upfgtp interface exists: ip link show upfgtp',
            'Check PFCP Session state',
            'Review UPF startup logs',
            'Verify N3 interface configuration'
        ],
        severity: 'critical',
        layer: 'GTP'
    },
    'ENCAP_FAILED': {
        code: '10',
        name: 'Encapsulation Failed',
        description: 'Failed to encapsulate packet in GTP-U tunnel (downlink direction).',
        impact: 'Downlink packet to UE dropped. UE will not receive data.',
        possibleCauses: [
            'Missing outer header creation info',
            'Invalid gNB F-TEID',
            'Memory allocation failure',
            'gtp5g module internal error',
            'Socket buffer allocation failed'
        ],
        suggestedActions: [
            'Check gtp5g module status: lsmod | grep gtp5g',
            'Review dmesg for gtp5g errors',
            'Verify FAR Outer Header Creation parameters',
            'Check system memory availability',
            'Verify gNB endpoint IP reachability'
        ],
        severity: 'critical',
        layer: 'GTP'
    },
    'DECAP_FAILED': {
        code: '11',
        name: 'Decapsulation Failed',
        description: 'Failed to decapsulate GTP-U packet (uplink direction). Cannot extract inner IP packet.',
        impact: 'Uplink data from UE dropped. UE uploads will fail.',
        possibleCauses: [
            'Corrupted GTP header',
            'Invalid extension headers',
            'Unsupported GTP version',
            'gtp5g module bug',
            'Packet truncation'
        ],
        suggestedActions: [
            'Capture and analyze GTP packets',
            'Check gtp5g module logs',
            'Verify GTP-U version compatibility',
            'Update gtp5g module if needed',
            'Check for packet fragmentation issues'
        ],
        severity: 'critical',
        layer: 'GTP'
    },
    'ROUTING_DROP': {
        code: '12',
        name: 'Routing Drop',
        description: 'Packet dropped due to routing decision. No route to destination or route unreachable.',
        impact: 'Packet cannot reach destination. Connectivity failure.',
        possibleCauses: [
            'No route to destination network',
            'Next hop unreachable',
            'Reverse path filtering (rp_filter)',
            'Policy routing rule blocked',
            'VRF/namespace routing issue'
        ],
        suggestedActions: [
            'Check routing table: ip route show',
            'Verify next hop reachability',
            'Check rp_filter: sysctl net.ipv4.conf.all.rp_filter',
            'Review policy routing: ip rule show',
            'Check network namespace configuration'
        ],
        severity: 'warning',
        layer: 'Routing'
    },
    'POLICY_DROP': {
        code: '13',
        name: 'Policy Drop',
        description: 'Packet dropped by access control policy (ACL/firewall rule).',
        impact: 'Traffic blocked by policy. May be intentional security measure.',
        possibleCauses: [
            'iptables/nftables rule blocked packet',
            'UPF access control list',
            'Security policy enforcement',
            'Application filter rule',
            'URL/content filtering'
        ],
        suggestedActions: [
            'Review firewall rules: iptables -L -n -v',
            'Check UPF policy configuration',
            'Verify application detection rules',
            'Review security policies',
            'Check if traffic should be allowed'
        ],
        severity: 'info',
        layer: 'Routing'
    },
    'MEMORY_ERROR': {
        code: '14',
        name: 'Memory Error',
        description: 'Memory allocation failure. System is under memory pressure.',
        impact: 'Packets dropped due to OOM. System stability at risk.',
        possibleCauses: [
            'System out of memory',
            'Memory fragmentation',
            'Memory leak in kernel module',
            'Too many sessions consuming memory',
            'sk_buff allocation failure'
        ],
        suggestedActions: [
            'Check system memory: free -h',
            'Monitor OOM killer: dmesg | grep -i oom',
            'Review session count and memory usage',
            'Consider adding more RAM',
            'Check for memory leaks: slabtop'
        ],
        severity: 'critical',
        layer: 'Kernel'
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
