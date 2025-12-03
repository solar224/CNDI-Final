import time
from scapy.all import *
from scapy.contrib.gtp import GTP_U_Header

# Load PFCP support
try:
    load_contrib("pfcp")
except Exception as e:
    print("Could not load PFCP module. Attempting to import directly.")
    import scapy.contrib.pfcp

# Ensure PFCP class is available
if 'PFCP' not in globals():
    from scapy.contrib.pfcp import PFCP, PFCPAssociationSetupRequest, PFCPSessionEstablishmentRequest, \
        IE_RecoveryTimeStamp, IE_NodeId, IE_FTEID, IE_CreatePDR, IE_PDR_Id, IE_Precedence, IE_PDI, \
        IE_SourceInterface, IE_OuterHeaderRemoval, IE_FAR_Id, IE_CreateFAR, IE_ApplyAction, IE_CreateQER, \
        IE_QER_Id, IE_GateStatus, IE_QFI, IE_FSEID

# --- Configuration ---
UPF_IP = "10.100.200.5"
UPF_PFCP_PORT = 8805
UPF_GTP_PORT = 2152

# IDs
TARGET_TEID = 0x11223344
SEID = 0x1234567890

def setup_pfcp_session_with_closed_gate():
    print(f"[*] Sending PFCP Association & Session Establishment to {UPF_IP}...")
    
    # 1. PFCP Association Setup Request
    # Layer structure: IP / UDP / PFCP Header / Message Payload
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

    # 2. PFCP Session Establishment Request
    
    fteid = IE_FTEID(
        V4=1, 
        TEID=TARGET_TEID, 
        ipv4=UPF_IP
    )

    # PDR: Match incoming traffic on Access Interface
    create_pdr = IE_CreatePDR(
        IE_list=[
            IE_PDR_Id(id=1),
            IE_Precedence(precedence=100),
            IE_PDI(IE_list=[
                IE_SourceInterface(interface=0), # 0 = Access
                fteid
            ]),
            IE_OuterHeaderRemoval(header=0), # 0 = GTP-U/UDP/IP
            IE_FAR_Id(id=1), 
            IE_QER_Id(id=1) 
        ]
    )

    # FAR: Action = FORWARD (2)
    create_far = IE_CreateFAR(
        IE_list=[
            IE_FAR_Id(id=1),
            IE_ApplyAction(FORW=1) 
        ]
    )

    # QER: Uplink Gate CLOSED
    # ul: 1 = Closed, 0 = Open
    create_qer = IE_CreateQER(
        IE_list=[
            IE_QER_Id(id=1),
            IE_GateStatus(ul=1, dl=0), 
            IE_QFI(QFI=9)
        ]
    )

    # Create the full PFCP Packet
    # Note: 'S', 'seid', and 'seq' belong to the PFCP layer, not the Request layer.
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
    print("[*] PFCP Session sent. Waiting 2s for UPF/Kernel to apply rules...")
    time.sleep(2)

def send_blocked_gtp_packet():
    print(f"[*] Sending GTP Packet to {UPF_IP} with TEID 0x{TARGET_TEID:08X}")
    print(f"[*] Target: Trigger GTP5G_DROP_UL_GATE_CLOSED (Code 8)")

    inner_pkt = IP(src="10.60.0.1", dst="8.8.8.8") / ICMP()
    
    gtp_pkt = IP(dst=UPF_IP) / \
              UDP(sport=2152, dport=UPF_GTP_PORT) / \
              GTP_U_Header(teid=TARGET_TEID, gtp_type=255) / \
              inner_pkt

    send(gtp_pkt, count=3, verbose=True)

if __name__ == "__main__":
    try:
        setup_pfcp_session_with_closed_gate()
        send_blocked_gtp_packet()
        print("\n[*] Done. Check drop reason 8.")
    except Exception as e:
        print(f"Error: {e}")
