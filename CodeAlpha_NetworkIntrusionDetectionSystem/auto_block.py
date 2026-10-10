#!/usr/bin/env python3
"""Simple response mechanism: follow eve.json and block IPs that trigger
too many alerts, using iptables.

Runs in DRY-RUN mode by default (only prints). Use --enforce on a test box.

    sudo python3 auto_block.py --enforce --threshold 5
"""
import argparse
import json
import subprocess
import time
from collections import Counter

ap = argparse.ArgumentParser()
ap.add_argument("--log", default="/var/log/suricata/eve.json")
ap.add_argument("--threshold", type=int, default=5, help="alerts before blocking")
ap.add_argument("--enforce", action="store_true", help="actually run iptables")
ap.add_argument("--whitelist", nargs="*", default=["127.0.0.1"])
args = ap.parse_args()

counts, blocked = Counter(), set()


def block(ip):
    cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
    if args.enforce:
        subprocess.run(cmd, check=False)
        print(f"BLOCKED {ip}")
    else:
        print(f"[dry-run] would run: {' '.join(cmd)}")
    blocked.add(ip)


with open(args.log) as f:
    f.seek(0, 2)                       # jump to the end, like tail -f
    print("Watching for alerts... Ctrl+C to stop")
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.5)
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("event_type") != "alert":
            continue
        ip = ev.get("src_ip")
        if not ip or ip in args.whitelist or ip in blocked:
            continue
        counts[ip] += 1
        print(f"alert from {ip} ({counts[ip]}): {ev['alert']['signature']}")
        if counts[ip] >= args.threshold:
            block(ip)
