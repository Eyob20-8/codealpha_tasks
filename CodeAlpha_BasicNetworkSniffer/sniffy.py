#!/usr/bin/env python3
"""
Basic Network Sniffer - CodeAlpha Cyber Security Internship (Task 1)

Captures packets with scapy and prints the useful parts:
source/destination IP, protocol, ports, TCP flags and a short payload preview.

Needs root/admin because it uses raw sockets:
    sudo python3 sniffer.py -i eth0 -c 50
    sudo python3 sniffer.py -f "tcp port 80" -w capture.pcap

Only sniff networks you own or have permission to monitor.
"""
import argparse
import datetime
from collections import Counter

from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, DNS, Raw

proto_count = Counter()
saved_packets = []

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def payload_preview(pkt, max_len=60):
    """Return a printable preview of the packet payload (if any)."""
    if not pkt.haslayer(Raw):
        return ""
    data = bytes(pkt[Raw].load)[:max_len]
    # replace non printable bytes with a dot so the terminal doesn't go crazy
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def handle_packet(pkt):
    if IP in pkt:
        ip = pkt[IP]
        src, dst = ip.src, ip.dst
        proto = PROTO_NAMES.get(ip.proto, f"OTHER({ip.proto})")
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
        proto = "IPv6"
    else:
        # ARP and other non-IP stuff
        proto_count["NON-IP"] += 1
        print(f"[{now()}] {pkt.summary()}")
        return

    proto_count[proto] += 1
    saved_packets.append(pkt)

    extra = ""
    if TCP in pkt:
        t = pkt[TCP]
        extra = f"{t.sport} -> {t.dport}  flags={t.sprintf('%flags%')}"
    elif UDP in pkt:
        u = pkt[UDP]
        extra = f"{u.sport} -> {u.dport}"
        if DNS in pkt and pkt[DNS].qd is not None:
            extra += f"  DNS query: {pkt[DNS].qd.qname.decode(errors='ignore')}"
    elif ICMP in pkt:
        extra = f"type={pkt[ICMP].type} code={pkt[ICMP].code}"

    print(f"[{now()}] {proto:<5} {src} -> {dst}  len={len(pkt)}  {extra}")

    preview = payload_preview(pkt)
    if preview:
        print(f"           payload: {preview}")


def now():
    return datetime.datetime.now().strftime("%H:%M:%S")


def main():
    ap = argparse.ArgumentParser(description="Simple packet sniffer using scapy")
    ap.add_argument("-i", "--iface", help="interface to sniff on (default: scapy picks one)")
    ap.add_argument("-c", "--count", type=int, default=0, help="number of packets (0 = until Ctrl+C)")
    ap.add_argument("-f", "--filter", default="", help="BPF filter, e.g. 'tcp port 80'")
    ap.add_argument("-w", "--write", help="save captured packets to a .pcap file")
    args = ap.parse_args()

    print("Sniffing... press Ctrl+C to stop\n")
    try:
        sniff(iface=args.iface, filter=args.filter or None,
              prn=handle_packet, count=args.count, store=False)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("Permission denied - run with sudo / as Administrator.")
        return

    print("\n--- Summary ---")
    for name, n in proto_count.most_common():
        print(f"{name:<8} {n}")

    if args.write and saved_packets:
        wrpcap(args.write, saved_packets)
        print(f"\nSaved {len(saved_packets)} packets to {args.write}")


if __name__ == "__main__":
    main()
