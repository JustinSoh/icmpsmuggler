import sys
import base64
import binascii
import argparse
from scapy.all import sniff

def packet_handler(packet):
    if packet.haslayer('ICMP'):
        print("Received packet:", packet.payload)
        # Do something with the packet

def main(): 
    # intialise parser and extract out info
    while True: 
        sniff(filter="", prn=packet_handler, store=0)    

if __name__ == "__main__":
    main()
