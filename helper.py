import base64
import binascii
from scapy.all import  IP, ICMP, sr1


BASE64_ENCODING = "b64"
HEX_ENCODING = "hex"


def encodeData(input, type=BASE64_ENCODING):
    encodedInput = str.encode(input)
    
    if type == BASE64_ENCODING:
        return base64.b64encode(encodedInput)
    
    if type == HEX_ENCODING: 
        return binascii.hexlify(encodedInput)

def decodeData(input):
    decoded = base64.b64decode(input)
    return decoded


def sendPayload(src, dst , payload):
    packet = IP(dst=dst, src=src) / ICMP() / payload
    # Send the packet and wait for responses
    sr1(packet, verbose=False)
    
    
def splitPayload(encodedPayload, chunks):
    # if the chunks > size of the encoded payload
    if int(chunks) > len(encodedPayload):
        chunks = 1
    sizePerChunk = len(encodedPayload) // int(chunks)  # Use integer division to avoid float division
    payloads = []
    for i in range(0, len(encodedPayload), sizePerChunk):  # Iterate over the payload with step equal to sizePerChunk
        payloads.append(encodedPayload[i:i+sizePerChunk])  # Append each chunk to the payloads list
    return payloads

