import sys
import base64

from scapy.all import Ether, IP, ICMP, sr1, Raw

def encodeData(input, type="b64"):
    if type == "b64":
        return base64.b64encode(input)
    

# set your source and destination port
src = "10.211.55.2"
dst = "10.211.55.5"
payload = encodeData(b'thisisatestingpayload', "b64")

p = sr1(IP(dst=dst , src=src)/ ICMP() / (payload))
if p: 
    p.show()