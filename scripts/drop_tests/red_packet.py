import time
from scapy.all import *

# --- Load PFCP ---
try:
    load_contrib("pfcp")
except Exception:
    print("Could not load PFCP contrib. Importing directly.")
    import scapy.contrib.pfcp

# Ensure classes exist
if 'PFCP' not in globals():
    from scapy.contrib.pfcp import PFCP, PFCPAssociationSetupRequest, PFCPSessionEstablishmentRequest, \
        IE_RecoveryTimeStamp, IE_NodeId, IE_FTEID, IE_CreatePDR, IE_PDR_Id, IE_Precedence, IE_PDI, \
        IE_SourceInterface, IE_OuterHeaderRemoval, IE_FAR_Id, IE_CreateFAR, IE_ApplyAction, IE_CreateQER, \
        IE_QER_Id, IE_GateStatus, IE_QFI, IE_FSEID, IE_UE_IP_Address, IE_OuterHeaderCreation, IE_MBR

# --- Configuration ---
UPF_IP = "10.100.200.5"      # Docker UPF IP
UPF_PFCP_PORT = 8805

# NETWORK CONFIGURATION (CRITICAL)
# RAN IP must be in the same subnet as UPF to ensure 'find_ip4_route' succeeds
# UPF is 10.100.200.5/24. We use 10.100.200.99 for the Fake RAN.
RAN_IP = "10.100.200.99"     
UE_IP = "10.60.0.1"          
RAN_TEID = 0x55667788
SEID = 0x9988776655

def build_outer_header_creation(teid, ip):
    """
    Robustly constructs IE_OuterHeaderCreation by detecting available fields.
    Resolves the "General Drop" caused by missing hdr_creation in Kernel.
    """
    cls = IE_OuterHeaderCreation
    fields = [f.name for f in cls.fields_desc]
    kwargs = {}
    
    # We need to set the flag 0x0100 (GTP-U/UDP/IPv4)
    # Check all known variations in Scapy versions
    if "GTPUUDPIPV4" in fields: kwargs["GTPUUDPIPV4"] = 1
    elif "GTP_U_UDP_IPv4" in fields: kwargs["GTP_U_UDP_IPv4"] = 1
    elif "GTP_U_UDP_IPV4" in fields: kwargs["GTP_U_UDP_IPV4"] = 1
    elif "description" in fields: kwargs["description"] = 0x0100
    elif "header" in fields: kwargs["header"] = 0x0100
    elif "desc" in fields: kwargs["desc"] = 0x0100
    
    # Set IP
    if "ipv4" in fields: kwargs["ipv4"] = ip
    elif "IPv4" in fields: kwargs["IPv4"] = ip
    elif "ip" in fields: kwargs["ip"] = ip
        
    # Set TEID
    if "TEID" in fields: kwargs["TEID"] = teid
    elif "teid" in fields: kwargs["teid"] = teid

    return cls(**kwargs)

def build_mbr(bitrate):
    """Robustly constructs MBR IE"""
    cls = IE_MBR
    fields = [f.name for f in cls.fields_desc]
    kwargs = {}
    # Set both UL and DL limits
    if 'ul' in fields: kwargs['ul'] = bitrate
    elif 'UL' in fields: kwargs['UL'] = bitrate
    if 'dl' in fields: kwargs['dl'] = bitrate
    elif 'DL' in fields: kwargs['DL'] = bitrate
    
    if not kwargs: return cls(bitrate, bitrate) # Fallback
    return cls(**kwargs)

def setup_pfcp_downlink_policing():
    print(f"[*] Sending PFCP Session (Downlink, MBR=1 kbps) to {UPF_IP}...")
    
    # 1. Association
    assoc_req = IP(dst=UPF_IP)/UDP(sport=8805, dport=UPF_PFCP_PORT) / \
                PFCP(seq=1) / \
                PFCPAssociationSetupRequest(
                    IE_list=[
                        IE_RecoveryTimeStamp(timestamp=int(time.time())),
                        IE_NodeId(id_type="IPv4", id=UPF_IP)
                    ]
                )
    send(assoc_req, verbose=False)
    time.sleep(1)

    # 2. Session Establishment
    
    # PDR: Downlink (Source Interface = Core)
    create_pdr = IE_CreatePDR(
        IE_list=[
            IE_PDR_Id(id=1),
            IE_Precedence(precedence=100),
            IE_PDI(IE_list=[
                IE_SourceInterface(interface=1), # 1 = Core
                IE_UE_IP_Address(ipv4=UE_IP, V4=1)
            ]),
            IE_FAR_Id(id=1), 
            IE_QER_Id(id=1) 
        ]
    )

    # FAR: Action FORW + OuterHeaderCreation
    # This prevents the "Unknown RAN address" error (General Drop)
    ohc_ie = build_outer_header_creation(RAN_TEID, RAN_IP)
    
    create_far = IE_CreateFAR(
        IE_list=[
            IE_FAR_Id(id=1),
            IE_ApplyAction(FORW=1),
            ohc_ie
        ]
    )

    # QER: MBR = 1 (Throttling)
    mbr_ie = build_mbr(1) 

    create_qer = IE_CreateQER(
        IE_list=[
            IE_QER_Id(id=1),
            IE_GateStatus(ul=0, dl=0), # Gate Open
            mbr_ie,                    # Rate Limit Trigger
            IE_QFI(QFI=9)
        ]
    )

    pfcp_session_req = IP(dst=UPF_IP)/UDP(sport=8805, dport=UPF_PFCP_PORT) / \
                       PFCP(S=1, seid=0, seq=2) / \
                       PFCPSessionEstablishmentRequest(
                           IE_list=[
                               IE_NodeId(id_type="IPv4", id="10.100.200.1"), 
                               IE_FSEID(v4=1, seid=SEID, ipv4="10.100.200.1"),
                               create_pdr,
                               create_far,
                               create_qer
                           ]
                       )

    send(pfcp_session_req, verbose=True)
    print("[*] PFCP Session configured.")
    time.sleep(2)

def send_burst_downlink_packets():
    print(f"[*] Sending Downlink Burst to {UE_IP} via {UPF_IP}")
    print(f"[*] Expectation: Code 13 (Red Packet).")
    
    # Route: Send packets destined to UE directly to UPF container
    conf.route.add(host=UE_IP, gw=UPF_IP)

    # Payload: Must be large enough to overflow the Token Bucket quickly
    pkt = IP(src="8.8.8.8", dst=UE_IP) / ICMP() / Raw(b"X" * 1200)

    # Send 50 packets. 
    # MBR is 1. Token bucket will empty instantly. 
    # Packets will turn Red.
    send(pkt, count=50, inter=0.002, verbose=True)

if __name__ == "__main__":
    try:
        setup_pfcp_downlink_policing()
        send_burst_downlink_packets()
        print("\n[*] Done. Check drop reason.")
    except Exception as e:
        print(f"Error: {e}")
