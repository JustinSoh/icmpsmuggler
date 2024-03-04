import sys
import base64
import binascii
import argparse
from scapy.all import sniff

SESSION_START = False
session_byte = b''
def decodeData(input):
    decoded = base64.b64decode(input)
    return decoded

def packet_handler(packet):
    if packet.haslayer('ICMP') and packet['ICMP'].type == 8:
        global SESSION_START
        global session_byte

        if b'IyNAQCEh' in packet.load:
            SESSION_START = True
            session_byte = b''


        elif b'ISFAQCMj' in packet.load:
            SESSION_START = False
            session_byte = decodeData(session_byte)
            print(session_byte)
            
        else: 
            session_byte += packet.load

            
def main(): 
    # intialise parser and extract out info
    while True: 
        p = sniff(filter="icmp", prn=packet_handler, store=0)    

if __name__ == "__main__":
    main()
