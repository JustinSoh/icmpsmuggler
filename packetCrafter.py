import sys
from scapy.all import Ether, IP, ICMP, sr1, Raw

# set your source and destination port
src = "10.211.55.2"
dst = "10.211.55.5"
payload = "thisisatestingpayload"

p = sr1(IP(dst=dst , src=src)/ ICMP() / Raw(load=payload))
if p: 
    p.show()