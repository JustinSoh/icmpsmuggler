import sys
import base64
import binascii
import argparse
from scapy.all import sniff

def packet_handler(packet):
    if packet.haslayer('ICMP'):
        print("Received packetttt:", packet.summary())
        # Do something with the packet

def main(): 
    # intialise parser and extract out info
    sniff(filter="", prn=packet_handler, store=0)    

if __name__ == "__main__":
    main()
