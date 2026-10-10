#!/usr/bin/env python3
"""Read Suricata's eve.json and show which alerts fired, from which IPs.
Draws a bar chart (alerts.png) if matplotlib is installed.

    python3 alert_summary.py /var/log/suricata/eve.json
"""
import json
import sys
from collections import Counter

path = sys.argv[1] if len(sys.argv) > 1 else "/var/log/suricata/eve.json"
by_sig, by_src = Counter(), Counter()

with open(path) as f:
    for line in f:
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("event_type") != "alert":
            continue
        by_sig[ev["alert"]["signature"]] += 1
        by_src[ev.get("src_ip", "?")] += 1

total = sum(by_sig.values())
print(f"Total alerts: {total}\n")
print("Top signatures:")
for sig, n in by_sig.most_common(10):
    print(f"  {n:>4}  {'#' * min(n, 40)}  {sig}")
print("\nTop source IPs:")
for ip, n in by_src.most_common(10):
    print(f"  {n:>4}  {ip}")

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    names, counts = zip(*by_sig.most_common(8)) if by_sig else ([], [])
    plt.figure(figsize=(9, 4))
    plt.barh([n[:45] for n in names][::-1], list(counts)[::-1])
    plt.xlabel("alerts")
    plt.title("Suricata alerts by signature")
    plt.tight_layout()
    plt.savefig("alerts.png")
    print("\nChart saved to alerts.png")
except ImportError:
    print("\n(install matplotlib for a chart: pip install matplotlib)")
