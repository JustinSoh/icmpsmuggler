import sys
import base64
import binascii
import argparse
from scapy.all import sniff, ICMP, IP, Raw, send

SENDING_START_SEQ = "######"
SENDING_END_SEQ = "!!!!!!"
RECEIVING_START_SEQ = b'IyNAQCEh'
RECEVING_END_SEQ = b'ISFAQCMj'

SESSION_START = False
session_byte = b''

BASE64_ENCODING = "b64"
HEX_ENCODING = "hex"

ICMP_REPLY_CODE = 0

TEST_COMMAND = b'test'
TEST_REPLY = 'mamamamama'


def encodeData(input, type="b64"):
    encodedInput = str.encode(input)
    if type == BASE64_ENCODING:
        return base64.b64encode(encodedInput)
    
    if type == HEX_ENCODING: 
        return binascii.hexlify(encodedInput)
    
def replyPayload(packet, payload):
    # Craft custom ICMP echo reply packet
    reply_packet = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                   ICMP(type=ICMP_REPLY_CODE, id=packet[ICMP].id, seq=packet[ICMP].seq) / \
                   payload

    send(reply_packet)

def splitPayload(encodedPayload, chunks):
    # if the chunks > size of the encoded payload
    if int(chunks) > len(encodedPayload):
        chunks = 1
    sizePerChunk = len(encodedPayload) // int(chunks)  # Use integer division to avoid float division
    payloads = []
    for i in range(0, len(encodedPayload), sizePerChunk):  # Iterate over the payload with step equal to sizePerChunk
        payloads.append(encodedPayload[i:i+sizePerChunk])  # Append each chunk to the payloads list
    return payloads

def process_and_send(session_byte,packet):
    if session_byte == TEST_COMMAND:
        # encoded_reply = encodeData("reply of a test")
        replyPayload(packet, encodeData(SENDING_START_SEQ))
        replyPayload(packet, encodeData(TEST_REPLY))
        replyPayload(packet, encodeData(SENDING_END_SEQ))

def decodeData(input):
    decoded = base64.b64decode(input)
    return decoded

def packet_handler(packet):
    if packet.haslayer('ICMP') and packet['ICMP'].type == 8 :
        global SESSION_START
        global session_byte

        if RECEIVING_START_SEQ in packet.load:
            SESSION_START = True
            session_byte = b''


        elif RECEVING_END_SEQ in packet.load:
            SESSION_START = False
            session_byte = decodeData(session_byte)
            print(session_byte)
            process_and_send(session_byte,packet)


        else: 
            session_byte += packet.load

            
def main(): 
    # intialise parser and extract out info
    while True: 
        p = sniff(filter="icmp", prn=packet_handler, store=0)    

if __name__ == "__main__":
    main()
