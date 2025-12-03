#!/usr/bin/env python3
from scapy.all import *
from scapy.contrib.gtp import GTPHeader

FAKE_UPF_IP = "10.100.200.250"     # DESTINATION (fake UPF)
FAKE_SRC_IP = "10.10.10.10"        # anything
GTP_PORT = 2152

def echo_req():
    return GTPHeader(
        version=1,
        PT=1,
        S=1,
        gtp_type=1,
        teid=0,
        seq=99
    ) / Raw(b"\x01")

pkt = IP(src=FAKE_SRC_IP, dst=FAKE_UPF_IP) \
      / UDP(sport=2152, dport=GTP_PORT) \
      / echo_req()

print(f"[*] Sending Echo Request to non-existent UPF IP {FAKE_UPF_IP}")
print("[*] UPF will try to reply to this and fail → GTP5G_DROP_NO_ROUTE")

send(pkt, count=1, verbose=True)

