# CodeAlpha_BasicNetworkSniffer

Task 1 of the CodeAlpha Cyber Security internship: a small packet sniffer in Python using `scapy`.

## What it does
- captures live packets on an interface
- prints source/destination IP, protocol (TCP/UDP/ICMP), ports, TCP flags
- shows DNS queries and a short payload preview (non-printable bytes shown as dots)
- optional BPF filter and saving to a `.pcap` (open it in Wireshark)
- prints a protocol summary when you stop it

## Setup
```bash
pip install -r requirements.txt
```
On Windows install [Npcap](https://npcap.com) first.

## Usage
```bash
sudo python3 sniffer.py -i eth0 -c 50             # 50 packets
sudo python3 sniffer.py -f "udp port 53"          # only DNS
sudo python3 sniffer.py -f "tcp port 80" -w web.pcap
```

## Sample output
```
[14:02:11] TCP   192.168.1.5 -> 93.184.216.34  len=74  52344 -> 80  flags=S
[14:02:11] TCP   93.184.216.34 -> 192.168.1.5  len=74  80 -> 52344  flags=SA
[14:02:11] TCP   192.168.1.5 -> 93.184.216.34  len=420  52344 -> 80  flags=PA
           payload: GET / HTTP/1.1..Host: example.com..User-Agent: curl/8
[14:02:12] UDP   192.168.1.5 -> 192.168.1.1  len=72  41233 -> 53  DNS query: example.com.
```
(Replace with your own screenshot before submitting.)

## What I learned
- TCP handshake is visible as S -> SA -> A flags
- HTTP sends everything in plain text, so passwords on non-HTTPS sites can be read - that's why HTTPS matters
- Each layer wraps the next one: Ethernet > IP > TCP/UDP > data

## Legal note
Only capture traffic on networks you own or are allowed to test.
