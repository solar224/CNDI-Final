import time
from scapy.all import *
from scapy.contrib.gtp import GTP_U_Header

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
        IE_QER_Id, IE_GateStatus, IE_QFI, IE_FSEID, IE_UE_IP_Address, IE_OuterHeaderCreation

# --- Configuration ---
UPF_IP = "10.100.200.5"
UPF_PFCP_PORT = 8805
UPF_GTP_PORT = 2152

# IDs
TARGET_TEID = 0x11223344
SEID = 0x1234567890

# THE TRIGGER: A Reserved Class E IP Address.
# The Linux kernel generally refuses to route/transmit to this block.
# This causes ip_xmit to return an error.
BAD_DEST_IP = "240.0.0.1" 

def build_outer_header_creation(teid, ip):
    """
    Robustly constructs IE_OuterHeaderCreation (GTP-U/UDP/IPv4)
    Handles Scapy field name variations.
    """
    cls = IE_OuterHeaderCreation
    fields = [f.name for f in cls.fields_desc]
    kwargs = {}
    
    # Flag: GTP-U/UDP/IPv4 (0x0100)
    if "GTPUUDPIPV4" in fields: kwargs["GTPUUDPIPV4"] = 1
    elif "GTP_U_UDP_IPv4" in fields: kwargs["GTP_U_UDP_IPv4"] = 1
    elif "GTP_U_UDP_IPV4" in fields: kwargs["GTP_U_UDP_IPV4"] = 1
    elif "description" in fields: kwargs["description"] = 0x0100
    elif "header" in fields: kwargs["header"] = 0x0100
    
    # Destination IP
    if "ipv4" in fields: kwargs["ipv4"] = ip
    elif "IPv4" in fields: kwargs["IPv4"] = ip
    elif "ip" in fields: kwargs["ip"] = ip
        
    # TEID
    if "TEID" in fields: kwargs["TEID"] = teid
    elif "teid" in fields: kwargs["teid"] = teid

    return cls(**kwargs)

def setup_pfcp_session_bad_route():
    print(f"[*] Sending PFCP Session (Uplink, Dest={BAD_DEST_IP}) to {UPF_IP}...")

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
    
    # PDR: Uplink (Access Interface)
    # Matches incoming GTP packets with TARGET_TEID
    create_pdr = IE_CreatePDR(
        IE_list=[
            IE_PDR_Id(id=1),
            IE_Precedence(precedence=100),
            IE_PDI(IE_list=[
                IE_SourceInterface(interface=0), # 0 = Access
                IE_FTEID(V4=1, TEID=TARGET_TEID, ipv4=UPF_IP)
            ]),
            # We must remove the incoming GTP header before adding the new one
            IE_OuterHeaderRemoval(header=0), 
            IE_FAR_Id(id=1)
        ]
    )

    # FAR: Forwarding + Header Creation
    # We instruct UPF to encapsulate and send to BAD_DEST_IP
    ohc_ie = build_outer_header_creation(0x999999, BAD_DEST_IP)
    
    create_far = IE_CreateFAR(
        IE_list=[
            IE_FAR_Id(id=1),
            IE_ApplyAction(FORW=1),
            ohc_ie
        ]
    )

    pfcp_session_req = IP(dst=UPF_IP)/UDP(sport=8805, dport=UPF_PFCP_PORT) / \
                       PFCP(S=1, seid=0, seq=2) / \
                       PFCPSessionEstablishmentRequest(
                           IE_list=[
                               IE_NodeId(id_type="IPv4", id="10.100.200.1"), 
                               IE_FSEID(v4=1, seid=SEID, ipv4="10.100.200.1"),
                               create_pdr,
                               create_far
                           ]
                       )

    send(pfcp_session_req, verbose=True)
    print("[*] PFCP Session configured. Waiting 2s...")
    time.sleep(2)

def send_uplink_pkt():
    print(f"[*] Sending Uplink GTP Packet to {UPF_IP} (TEID 0x{TARGET_TEID:08X})...")
    print(f"[*] UPF will try to forward this to {BAD_DEST_IP}.")
    print(f"[*] Target: Trigger GTP5G_DROP_IP_XMIT_FAIL (Code 14)")

    # Inner packet (UE -> Internet)
    inner_pkt = IP(src="10.60.0.1", dst="8.8.8.8") / ICMP() / Raw(b"test_payload")
    
    # Encapsulate in GTP
    gtp_pkt = IP(dst=UPF_IP) / \
              UDP(sport=2152, dport=UPF_GTP_PORT) / \
              GTP_U_Header(teid=TARGET_TEID, gtp_type=255) / \
              inner_pkt

    send(gtp_pkt, count=3, verbose=True)

if __name__ == "__main__":
    try:
        setup_pfcp_session_bad_route()
        send_uplink_pkt()
        print("\n[*] Done. Check drop reason 14.")
    except Exception as e:
        print(f"Error: {e}")
