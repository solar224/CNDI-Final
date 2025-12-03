import time
from scapy.all import *

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
        IE_QER_Id, IE_GateStatus, IE_QFI, IE_FSEID, IE_UE_IP_Address, IE_OuterHeaderCreation

# --- Configuration ---
UPF_IP = "10.100.200.5"
UPF_PFCP_PORT = 8805

# Emulated UE and RAN details
UE_IP = "10.60.0.1"      # The target UE IP
RAN_IP = "10.100.200.20" # Fake gNB IP
RAN_TEID = 0x55667788    # Fake TEID at gNB
SEID = 0x9988776655

def get_outer_header_creation(teid, ip):
    """
    Dynamically determines the correct arguments for IE_OuterHeaderCreation
    based on the installed Scapy version fields.
    """
    cls = IE_OuterHeaderCreation
    fields = [f.name for f in cls.fields_desc]
    print(f"[*] Debug: IE_OuterHeaderCreation fields: {fields}")

    kwargs = {}
    
    # 1. Set the Flag for GTP-U/UDP/IPv4 (Bit 8 / Value 0x0100)
    # The debug logs showed 'GTPUUDPIPV4' is the correct name
    if "GTPUUDPIPV4" in fields:
        kwargs["GTPUUDPIPV4"] = 1
    elif "GTP_U_UDP_IPv4" in fields:
        kwargs["GTP_U_UDP_IPv4"] = 1
    elif "GTP_U_UDP_IPV4" in fields:
        kwargs["GTP_U_UDP_IPV4"] = 1
    elif "description" in fields:
        kwargs["description"] = 0x0100
    elif "header" in fields:
        kwargs["header"] = 0x0100
    else:
        print("[!] Error: Could not find matching Description/Flag field.")
        # Attempt minimal fallback, though likely to fail if bitfields are strict
        return cls(GTPUUDPIPV4=1, TEID=teid, ipv4=ip)

    # 2. Set IP Field
    if "ipv4" in fields:
        kwargs["ipv4"] = ip
    elif "IPv4" in fields:
        kwargs["IPv4"] = ip
    elif "ip" in fields:
        kwargs["ip"] = ip
        
    # 3. Set TEID Field
    if "TEID" in fields:
        kwargs["TEID"] = teid
    elif "teid" in fields:
        kwargs["teid"] = teid

    print(f"[*] Constructing IE_OuterHeaderCreation with: {kwargs}")
    return cls(**kwargs)

def setup_pfcp_dl_session_closed_gate():
    print(f"[*] Sending PFCP Session Establishment (Downlink, Gate Closed) to {UPF_IP}...")

    # 1. PFCP Association Setup
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

    # 2. PFCP Session Establishment Request (Downlink Rule)
    
    # PDR: Match traffic from Core (1) to UE IP
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

    # FAR: Action = FORWARD + Encapsulate
    # Use the helper to construct the tricky IE
    ohc_ie = get_outer_header_creation(RAN_TEID, RAN_IP)
    
    create_far = IE_CreateFAR(
        IE_list=[
            IE_FAR_Id(id=1),
            IE_ApplyAction(FORW=1),
            ohc_ie
        ]
    )

    # QER: Downlink Gate CLOSED
    # ul: 0 (Open), dl: 1 (Closed)
    create_qer = IE_CreateQER(
        IE_list=[
            IE_QER_Id(id=1),
            IE_GateStatus(ul=0, dl=1), 
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
    print("[*] PFCP Session sent. Waiting 2s for UPF/Kernel...")
    time.sleep(2)

def send_blocked_downlink_packet():
    print(f"[*] Sending Downlink IP Packet for {UE_IP} via {UPF_IP}")
    print(f"[*] Target: Trigger GTP5G_DROP_DL_GATE_CLOSED (Code 9)")

    # Route packet via UPF
    conf.route.add(host=UE_IP, gw=UPF_IP)

    # Packet simulates Internet -> UE
    pkt = IP(src="8.8.8.8", dst=UE_IP) / ICMP() / Raw(load="Payload" * 10)

    # Send
    send(pkt, count=3, verbose=True)

if __name__ == "__main__":
    try:
        setup_pfcp_dl_session_closed_gate()
        send_blocked_downlink_packet()
        print("\n[*] Done. Check drop reason 9.")
    except Exception as e:
        print(f"Error: {e}")
