<!-- No_PDR (code 6) Drop Test -->

```
cat > /tmp/test_no_pdr.py << 'EOF'
"""
Test NO_PDR drop: Send GTP-U packet with invalid/unknown TEID
"""
from scapy.all import *
from scapy.contrib.gtp import GTPHeader, GTP_U_Header
import sys

# UPF 的 N3 介面 IP (VM1)
UPF_IP = "192.168.56.103"
GTP_PORT = 2152

# 使用一個不存在的 TEID
INVALID_TEID = 0xDEADBEEF

# 建立 GTP-U 封包 (帶有無效的 TEID)
# 內部 IP 封包: 假裝是從 UE 發出
inner_ip = IP(src="10.60.0.99", dst="8.8.8.8") / ICMP() / Raw(b"test_no_pdr")

# GTP-U 封裝 (使用 GTP_U_Header)
gtp_header = GTP_U_Header(
    gtp_type=255,   # G-PDU (user data)
    teid=INVALID_TEID,
) / inner_ip

# 外部 UDP/IP 封包 (模擬 gNB -> UPF)
pkt = IP(src="192.168.56.104", dst=UPF_IP) / UDP(sport=2152, dport=GTP_PORT) / gtp_header

print(f"Sending GTP-U packet with TEID=0x{INVALID_TEID:08X} to {UPF_IP}:{GTP_PORT}")
print(f"This should trigger NO_PDR drop (Code 6)")

# 發送封包
send(pkt, count=5, inter=0.1, verbose=True)
print("Done! Check 5G-DPOP agent for drop events.")
EOF

# 3. 執行測試
sudo python3 /tmp/test_no_pdr.py

```