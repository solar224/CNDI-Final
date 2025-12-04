from scapy.all import *
import struct

# Configuration based on your docker-compose
UPF_IP = "10.100.200.5"
UPF_PORT = 2152

def send_invalid_ext_len_pkt():
    print(f"[*] Sending Malformed GTP packet to {UPF_IP}:{UPF_PORT}...")
    print(f"[*] Target: Trigger GTP5G_DROP_INVALID_EXT_HDR (Code 5)")

    # --- 1. Outer IP/UDP Header ---
    ip_layer = IP(dst=UPF_IP)
    udp_layer = UDP(sport=12345, dport=UPF_PORT)

    # --- 2. Constructing Malformed GTP Header Manually ---
    
    # Byte 0: Flags
    # Version=1 (0x20) | PT=1 (0x10) | E-flag=1 (0x04)
    # E-flag is crucial to tell Kernel to look for extensions.
    gtp_flags = 0x34 
    
    # Byte 1: Message Type (255 = G-PDU/T-PDU)
    gtp_type = 255
    
    # Byte 4-7: TEID (Arbitrary, check happens before PDR lookup completes)
    teid = 0x12345678

    # --- Optional Header (Required because E-flag is 1) ---
    # Byte 8-9: Sequence Number (Unused, 0)
    # Byte 10: N-PDU Number (Unused, 0)
    # Byte 11: Next Extension Header Type. 
    # MUST be non-zero to enter the kernel loop: while (*(ext_hdr = ...))
    # 0x85 is PDU Session Container, but any non-zero value works.
    next_ext_type = 0x85 

    opt_header = struct.pack("!HBB", 0, 0, next_ext_type)

    # --- The Malformed Extension Header ---
    # The kernel logic is: extlen = (*(ptr)) * 4;
    # If extlen == 0, it drops.
    # So we set the first byte (Length) to 0x00.
    malformed_ext_header = b'\x00' + b'\xAA\xBB\xCC' # Padding

    # Payload (Dummy inner IP packet)
    inner_packet = bytes(IP(src="10.60.0.1", dst="8.8.8.8")/ICMP())

    # Calculate Total GTP Length
    # Length = Optional Header + Ext Header + Payload
    # (Standard excludes the mandatory 8 bytes of header)
    total_len = len(opt_header) + len(malformed_ext_header) + len(inner_packet)
    
    # Pack the Mandatory Header: Flags, Type, Length, TEID
    gtp_mandatory = struct.pack("!BBHI", gtp_flags, gtp_type, total_len, teid)

    # Combine all parts
    raw_gtp_payload = gtp_mandatory + opt_header + malformed_ext_header + inner_packet

    # Create the full packet
    pkt = ip_layer / udp_layer / Raw(load=raw_gtp_payload)

    # Send
    send(pkt, count=5, verbose=True)

if __name__ == "__main__":
    send_invalid_ext_len_pkt()
