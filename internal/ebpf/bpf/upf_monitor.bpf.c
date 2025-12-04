// go:build ignore

// upf_monitor.bpf.c - eBPF program to monitor gtp5g kernel module
// This program hooks into gtp5g functions to collect traffic statistics
// and detect packet drops.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// Constants
#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17
#define IPPROTO_TCP 6
#define GTP_U_PORT 2152

// Traffic direction
#define DIRECTION_UPLINK 0
#define DIRECTION_DOWNLINK 1

// Drop reasons - Direct mapping from gtp5g error codes (1:1)
// These match exactly with gtp5g/src/gtpu/encap.c definitions
#define DROP_REASON_PKT_DROPPED 1      // Generic packet dropped
#define DROP_REASON_ECHO_RESP_CREATE 2 // GTP Echo Response creation failed
#define DROP_REASON_NO_ROUTE 3         // No route to destination
#define DROP_REASON_PULL_FAILED 4      // skb_pull failed
#define DROP_REASON_INVALID_EXT_HDR 5  // Invalid GTP extension header
#define DROP_REASON_NO_PDR 6           // No PDR rule matched
#define DROP_REASON_GENERAL 7          // General error
#define DROP_REASON_UL_GATE_CLOSED 8   // Uplink gate closed (QoS)
#define DROP_REASON_DL_GATE_CLOSED 9   // Downlink gate closed (QoS)
#define DROP_REASON_PDR_NULL 10        // PDR pointer is NULL
#define DROP_REASON_NO_F_TEID 11       // No F-TEID found
#define DROP_REASON_URR_REPORT_FAIL 12 // URR report failed
#define DROP_REASON_RED_PACKET 13      // QoS RED drop
#define DROP_REASON_IP_XMIT_FAIL 14    // IP transmit failed
#define DROP_REASON_NOT_TPDU 15        // Not a T-PDU
#define DROP_REASON_PULL_HDR_FAIL 16   // Header pull failed
#define DROP_REASON_NETIF_RX_FAIL 17   // netif_rx failed
#define DROP_REASON_UNKNOWN 255        // Unknown/other reasons

// ============================================================================
// Data Structures
// ============================================================================

// Traffic counter structure
struct traffic_counter
{
    __u64 packets;
    __u64 bytes;
    __u64 timestamp;
};

// Drop event structure (sent to userspace via ring buffer)
struct drop_event
{
    __u64 timestamp;
    __u32 teid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 pkt_len;
    __u8 reason;
    __u8 direction;
    __u8 pad[2];
};

// Packet event structure (for detailed tracing)
struct packet_event
{
    __u64 timestamp;
    __u32 teid;
    __u32 src_ip;
    __u32 dst_ip;
    __u32 pkt_len;
    __u8 direction;
    __u8 qfi;
    __u8 pad[2];
};

// Session info (populated from userspace via PFCP sniffer)
struct session_info
{
    __u64 seid;
    __u32 ue_ip;
    __u32 upf_ip;
    __u64 created_at;
};

// ============================================================================
// BPF Maps
// ============================================================================

// Per-CPU traffic counters (avoids lock contention)
// Key: 0 = uplink, 1 = downlink
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct traffic_counter);
} traffic_stats SEC(".maps");

// Ring buffer for drop events (sent to userspace)
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB
} drop_events SEC(".maps");

// Ring buffer for packet events (optional detailed tracing)
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024); // 512KB
} packet_events SEC(".maps");

// TEID to Session mapping (populated from userspace)
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32); // TEID
    __type(value, struct session_info);
} teid_session_map SEC(".maps");

// Per-TEID counters (for uplink, keyed by TEID)
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32); // TEID
    __type(value, struct traffic_counter);
} teid_stats SEC(".maps");

// Per-UE IP counters (for downlink, keyed by UE IP)
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32); // UE IP address
    __type(value, struct traffic_counter);
} ue_ip_stats SEC(".maps");

// Configuration flags (set from userspace)
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} agent_config SEC(".maps");

// Pending packet info - for passing data from kprobe to kretprobe
// Keyed by task PID to support concurrent packets
struct pending_pkt_info
{
    __u32 teid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 pkt_len;
    __u8 direction;
    __u8 valid;
    __u8 pad[2];
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); // PID/TID
    __type(value, struct pending_pkt_info);
} pending_pkts SEC(".maps");

// ============================================================================
// Helper Functions
// ============================================================================

static __always_inline void update_traffic_counter(__u32 direction, __u32 len)
{
    struct traffic_counter *counter;

    counter = bpf_map_lookup_elem(&traffic_stats, &direction);
    if (counter)
    {
        counter->packets++;
        counter->bytes += len;
        counter->timestamp = bpf_ktime_get_ns();
    }
}

static __always_inline void update_teid_counter(__u32 teid, __u32 len)
{
    struct traffic_counter *counter;
    struct traffic_counter new_counter = {0};

    counter = bpf_map_lookup_elem(&teid_stats, &teid);
    if (counter)
    {
        counter->packets++;
        counter->bytes += len;
        counter->timestamp = bpf_ktime_get_ns();
    }
    else
    {
        new_counter.packets = 1;
        new_counter.bytes = len;
        new_counter.timestamp = bpf_ktime_get_ns();
        bpf_map_update_elem(&teid_stats, &teid, &new_counter, BPF_ANY);
    }
}

// Update per-UE IP counter (for downlink traffic)
static __always_inline void update_ue_ip_counter(__u32 ue_ip, __u32 len)
{
    struct traffic_counter *counter;
    struct traffic_counter new_counter = {0};

    if (ue_ip == 0)
        return;

    counter = bpf_map_lookup_elem(&ue_ip_stats, &ue_ip);
    if (counter)
    {
        counter->packets++;
        counter->bytes += len;
        counter->timestamp = bpf_ktime_get_ns();
    }
    else
    {
        new_counter.packets = 1;
        new_counter.bytes = len;
        new_counter.timestamp = bpf_ktime_get_ns();
        bpf_map_update_elem(&ue_ip_stats, &ue_ip, &new_counter, BPF_ANY);
    }
}

static __always_inline void emit_drop_event(__u32 teid, __u32 src_ip, __u32 dst_ip,
                                            __u16 src_port, __u16 dst_port,
                                            __u32 pkt_len, __u8 reason, __u8 direction)
{
    struct drop_event *event;

    event = bpf_ringbuf_reserve(&drop_events, sizeof(*event), 0);
    if (!event)
    {
        return;
    }

    event->timestamp = bpf_ktime_get_ns();
    event->teid = teid;
    event->src_ip = src_ip;
    event->dst_ip = dst_ip;
    event->pkt_len = pkt_len;
    event->reason = reason;
    event->direction = direction;
    event->src_port = src_port;
    event->dst_port = dst_port;

    bpf_ringbuf_submit(event, 0);
}

static __always_inline void emit_packet_event(__u32 teid, __u32 src_ip, __u32 dst_ip,
                                              __u32 pkt_len, __u8 direction, __u8 qfi)
{
    struct packet_event *event;

    // Check if detailed tracing is enabled
    __u32 key = 0; // config key for detailed_tracing
    __u32 *enabled = bpf_map_lookup_elem(&agent_config, &key);
    if (!enabled || *enabled == 0)
    {
        return;
    }

    event = bpf_ringbuf_reserve(&packet_events, sizeof(*event), 0);
    if (!event)
    {
        return;
    }

    event->timestamp = bpf_ktime_get_ns();
    event->teid = teid;
    event->src_ip = src_ip;
    event->dst_ip = dst_ip;
    event->pkt_len = pkt_len;
    event->direction = direction;
    event->qfi = qfi;

    bpf_ringbuf_submit(event, 0);
}

// ============================================================================
// gtp5g error code pass-through (1:1 mapping)
// No conversion needed - we pass the error_code directly as drop reason
// ============================================================================
static __always_inline __u8 map_gtp5g_error_to_reason(int error_code)
{
    // Direct pass-through: gtp5g error codes 1-17 map to drop reasons 1-17
    if (error_code >= 1 && error_code <= 17)
    {
        return (__u8)error_code;
    }
    return DROP_REASON_UNKNOWN;
}

// ============================================================================
// Kprobes - Hook gtp5g functions
// ============================================================================

// Hook: gtp5g_trace_drop - THE PRIMARY DROP DETECTION HOOK
// This is called by gtp5g whenever a packet is dropped with specific reason
SEC("kprobe/gtp5g_trace_drop")
int BPF_KPROBE(kprobe_gtp5g_trace_drop, int error_code, struct sk_buff *skb)
{
    __u32 len = 0;
    __u32 teid = 0;
    __u32 src_ip = 0, dst_ip = 0;
    __u16 src_port = 0, dst_port = 0;
    __u8 reason;
    __u8 direction = 0; // Will try to determine from packet
    unsigned char *head;
    __u16 transport_header;
    __u16 network_header;

    // Map gtp5g error code to our drop reason
    // gtp5g error codes 1-17 map directly to drop reasons 1-17
    if (error_code >= 1 && error_code <= 17)
    {
        reason = (__u8)error_code;
    }
    else
    {
        reason = DROP_REASON_UNKNOWN;
    }

    if (!skb)
    {
        // Even without skb, we should record the drop with the reason
        emit_drop_event(0, 0, 0, 0, 0, 0, reason, 0);
        return 0;
    }

    // Read packet length
    len = BPF_CORE_READ(skb, len);

    // Try to extract packet info
    head = BPF_CORE_READ(skb, head);
    transport_header = BPF_CORE_READ(skb, transport_header);
    network_header = BPF_CORE_READ(skb, network_header);

    if (head && network_header > 0)
    {
        unsigned char *ip_header = head + network_header;
        bpf_probe_read_kernel(&src_ip, sizeof(src_ip), ip_header + 12);
        bpf_probe_read_kernel(&dst_ip, sizeof(dst_ip), ip_header + 16);
    }

    if (head && transport_header > 0)
    {
        unsigned char *udp_header = head + transport_header;
        bpf_probe_read_kernel(&src_port, sizeof(src_port), udp_header);
        bpf_probe_read_kernel(&dst_port, sizeof(dst_port), udp_header + 2);
        src_port = bpf_ntohs(src_port);
        dst_port = bpf_ntohs(dst_port);

        // If destination port is GTP-U (2152), likely uplink
        if (dst_port == GTP_U_PORT)
        {
            direction = DIRECTION_UPLINK;
            // Try to extract TEID from GTP header
            unsigned char *gtp_header = head + transport_header + 8;
            bpf_probe_read_kernel(&teid, sizeof(teid), gtp_header + 4);
            teid = bpf_ntohl(teid);
        }
        else if (src_port == GTP_U_PORT)
        {
            direction = DIRECTION_DOWNLINK;
        }
    }

    emit_drop_event(teid, src_ip, dst_ip, src_port, dst_port, len, reason, direction);

    return 0;
}

// Hook: gtp5g_encap_recv - Entry point for uplink packets
// This function is called when a GTP-U packet is received on the UDP socket
SEC("kprobe/gtp5g_encap_recv")
int BPF_KPROBE(kprobe_gtp5g_encap_recv, struct sock *sk, struct sk_buff *skb)
{
    __u32 len;
    __u32 teid = 0;
    __u32 src_ip = 0, dst_ip = 0;
    __u16 src_port = 0, dst_port = 0;
    unsigned char *head;
    __u16 transport_header;
    __u16 network_header;
    __u32 pid;
    struct pending_pkt_info pkt_info = {0};

    if (!skb)
    {
        return 0;
    }

    // Read packet length
    len = BPF_CORE_READ(skb, len);

    // Update uplink counter
    update_traffic_counter(DIRECTION_UPLINK, len);

    // Extract TEID from GTP-U header
    // GTP-U header: Flags(1) + Type(1) + Length(2) + TEID(4)
    // TEID is at offset 4 from the start of GTP header
    head = BPF_CORE_READ(skb, head);
    transport_header = BPF_CORE_READ(skb, transport_header);
    network_header = BPF_CORE_READ(skb, network_header);

    if (head && transport_header > 0)
    {
        // UDP header is 8 bytes, GTP-U header starts after UDP
        // GTP TEID is at offset 4 of GTP header
        unsigned char *gtp_header = head + transport_header + 8; // skip UDP header
        bpf_probe_read_kernel(&teid, sizeof(teid), gtp_header + 4);
        teid = bpf_ntohl(teid);

        // Read outer IP header for src/dst
        if (network_header > 0)
        {
            unsigned char *ip_header = head + network_header;
            bpf_probe_read_kernel(&src_ip, sizeof(src_ip), ip_header + 12);
            bpf_probe_read_kernel(&dst_ip, sizeof(dst_ip), ip_header + 16);
        }

        // Read UDP ports
        unsigned char *udp_header = head + transport_header;
        bpf_probe_read_kernel(&src_port, sizeof(src_port), udp_header);
        bpf_probe_read_kernel(&dst_port, sizeof(dst_port), udp_header + 2);
        src_port = bpf_ntohs(src_port);
        dst_port = bpf_ntohs(dst_port);

        if (teid > 0)
        {
            update_teid_counter(teid, len);

            // Emit packet event for detailed tracking
            emit_packet_event(teid, src_ip, dst_ip, len, DIRECTION_UPLINK, 0);
        }
    }

    // Save packet info for kretprobe
    pid = bpf_get_current_pid_tgid() >> 32;
    pkt_info.teid = teid;
    pkt_info.src_ip = src_ip;
    pkt_info.dst_ip = dst_ip;
    pkt_info.src_port = src_port;
    pkt_info.dst_port = dst_port;
    pkt_info.pkt_len = len;
    pkt_info.direction = DIRECTION_UPLINK;
    pkt_info.valid = 1;
    bpf_map_update_elem(&pending_pkts, &pid, &pkt_info, BPF_ANY);

    return 0;
}

// Hook: gtp5g_dev_xmit - Entry point for downlink packets
// This function is called when a packet is transmitted through upfgtp interface
SEC("kprobe/gtp5g_dev_xmit")
int BPF_KPROBE(kprobe_gtp5g_dev_xmit, struct sk_buff *skb, struct net_device *dev)
{
    __u32 len;
    __u32 teid = 0;
    __u32 src_ip = 0, dst_ip = 0;
    unsigned char *data;
    __u32 data_len;
    __u32 pid;
    struct pending_pkt_info pkt_info = {0};

    if (!skb)
    {
        return 0;
    }

    // Read packet length
    len = BPF_CORE_READ(skb, len);

    // Update downlink counter
    update_traffic_counter(DIRECTION_DOWNLINK, len);

    // For downlink, we need to find the destination TEID
    // The TEID will be added during encapsulation, but we can try to
    // look it up from the inner IP destination address
    data = BPF_CORE_READ(skb, data);
    data_len = BPF_CORE_READ(skb, len);

    if (data && data_len >= 20)
    {
        // Read inner IP header to get source and destination (UE IP)
        bpf_probe_read_kernel(&src_ip, sizeof(src_ip), data + 12); // IP src at offset 12
        bpf_probe_read_kernel(&dst_ip, sizeof(dst_ip), data + 16); // IP dst at offset 16

        // Update per-UE IP counter for downlink traffic
        if (dst_ip > 0)
        {
            update_ue_ip_counter(dst_ip, len);
            emit_packet_event(0, src_ip, dst_ip, len, DIRECTION_DOWNLINK, 0);
        }
    }

    // Save packet info for kretprobe
    pid = bpf_get_current_pid_tgid() >> 32;
    pkt_info.teid = teid;
    pkt_info.src_ip = src_ip;
    pkt_info.dst_ip = dst_ip;
    pkt_info.src_port = 0;
    pkt_info.dst_port = 0;
    pkt_info.pkt_len = len;
    pkt_info.direction = DIRECTION_DOWNLINK;
    pkt_info.valid = 1;
    bpf_map_update_elem(&pending_pkts, &pid, &pkt_info, BPF_ANY);

    return 0;
}

// Hook: gtp5g_handle_skb - Internal packet handling (if available)
// Some versions of gtp5g have this function for packet processing
SEC("kprobe/gtp5g_handle_skb")
int BPF_KPROBE(kprobe_gtp5g_handle_skb, struct sk_buff *skb)
{
    // This is a placeholder - actual implementation depends on gtp5g version
    return 0;
}

// Hook: kretprobe for pdr_find_by_gtp1u - Detect PDR lookup failures
// NOTE: Drop events are now captured by kprobe_gtp5g_trace_drop which is more reliable
// This kretprobe is kept for potential future use but does not emit drop events
SEC("kretprobe/pdr_find_by_gtp1u")
int BPF_KRETPROBE(kretprobe_pdr_find_by_gtp1u, void *ret)
{
    // kprobe_gtp5g_trace_drop now handles all drop detection
    // This hook is kept as a backup but doesn't emit events to avoid duplicates
    return 0;
}

// Hook: kretprobe for pdr_find_by_ipv4 - Detect PDR lookup failures (downlink)
// NOTE: Drop events are now captured by kprobe_gtp5g_trace_drop which is more reliable
// This kretprobe is kept for potential future use but does not emit drop events
SEC("kretprobe/pdr_find_by_ipv4")
int BPF_KRETPROBE(kretprobe_pdr_find_by_ipv4, void *ret)
{
    // kprobe_gtp5g_trace_drop now handles all drop detection
    // This hook is kept as a backup but doesn't emit events to avoid duplicates
    return 0;
}

// NOTE: kretprobe for gtp5g_encap_recv and gtp5g_dev_xmit were REMOVED
// because they always return 0 (NETDEV_TX_OK) even on errors.
// Drop detection is now handled by kprobe/gtp5g_trace_drop which is
// the proper hook point that gtp5g calls for all drop events.

// Hook: kfree_skb tracepoint - Detect packet drops
// This tracepoint fires whenever a packet is dropped in the kernel
SEC("tracepoint/skb/kfree_skb")
int tracepoint_kfree_skb(struct trace_event_raw_kfree_skb *ctx)
{
    struct sk_buff *skb;
    void *location;
    __u32 len;
    __u8 reason = DROP_REASON_GENERAL; // Code 7: General kernel drop

    // Check if drop tracing is enabled (config key 1)
    __u32 key = 1;
    __u32 *enabled = bpf_map_lookup_elem(&agent_config, &key);
    if (!enabled || *enabled == 0)
    {
        return 0;
    }

    skb = (struct sk_buff *)ctx->skbaddr;
    location = (void *)ctx->location;

    if (!skb)
    {
        return 0;
    }

    // Read packet length
    len = BPF_CORE_READ(skb, len);

    // Only emit if packet has meaningful length (filter noise)
    if (len < 20)
    {
        return 0;
    }

// Try to determine more specific drop reason from drop_reason field (kernel 5.17+)
// The drop_reason is available in newer kernels
#ifdef BPF_CORE_READ_USER
    __u32 drop_reason = 0;
// ctx->reason available in newer kernels
#endif

    emit_drop_event(0, 0, 0, 0, 0, len, reason, 0);

    return 0;
}

// Hook: nf_hook_slow - Detect netfilter drops (firewall/iptables)
// This catches packets dropped by iptables rules
SEC("kprobe/nf_hook_slow")
int BPF_KPROBE(kprobe_nf_hook_slow, struct sk_buff *skb)
{
    // Check if this tracing is enabled
    __u32 key = 2; // config key for netfilter tracing
    __u32 *enabled = bpf_map_lookup_elem(&agent_config, &key);
    if (!enabled || *enabled == 0)
    {
        return 0;
    }

    // This is entry probe, we need kretprobe to check verdict
    return 0;
}

// Hook: ip_forward - Track forwarded packets
SEC("kprobe/ip_forward")
int BPF_KPROBE(kprobe_ip_forward, struct sk_buff *skb)
{
    // Track IP forwarding for routing analysis
    return 0;
}

// Hook: kretprobe for ip_forward - Detect routing drops
SEC("kretprobe/ip_forward")
int BPF_KRETPROBE(kretprobe_ip_forward, int ret)
{
    __u32 key = 2;
    __u32 *enabled = bpf_map_lookup_elem(&agent_config, &key);
    if (!enabled || *enabled == 0)
    {
        return 0;
    }

    if (ret != 0)
    {
        emit_drop_event(0, 0, 0, 0, 0, 0, DROP_REASON_NO_ROUTE, 0); // Code 3: No route
    }
    return 0;
}

// ============================================================================
// License
// ============================================================================

char LICENSE[] SEC("license") = "GPL";
