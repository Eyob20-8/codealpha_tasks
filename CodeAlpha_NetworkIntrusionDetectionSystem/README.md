# CodeAlpha_NetworkIntrusionDetectionSystem

Task 4: network based IDS with **Suricata** on Ubuntu, custom rules, continuous monitoring,
an automatic response script and an alert dashboard.

## Files
| file | purpose |
|------|---------|
| `local.rules` | my custom detection rules (ping, port scan, SSH brute force, SQLi, traversal, XSS, scanner UA, .xyz DNS) |
| `attack_tests.sh` | generates test traffic from another machine to trigger the rules |
| `auto_block.py` | response mechanism: blocks an IP with iptables after N alerts (dry-run by default) |
| `alert_summary.py` | reads `eve.json`, prints top alerts/IPs and saves `alerts.png` |
| `sample_eve.json` | sample log so the dashboard script can be tried without Suricata |

## 1. Install
```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update && sudo apt install suricata -y
sudo suricata-update          # download the free ET Open ruleset
```

## 2. Configure
Edit `/etc/suricata/suricata.yaml`:
```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.1.0/24]"     # change to your network
af-packet:
  - interface: eth0                  # change to your interface (ip a)
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
  - /etc/suricata/rules/local.rules
```
Copy my rules and test the config:
```bash
sudo cp local.rules /etc/suricata/rules/local.rules
sudo suricata -T -c /etc/suricata/suricata.yaml -v     # should say "configuration provided was successfully loaded"
```

## 3. Run (continuous monitoring)
```bash
sudo systemctl enable --now suricata
sudo tail -f /var/log/suricata/fast.log
```

## 4. Test
From a second VM (Kali works well):
```bash
./attack_tests.sh <ip-of-suricata-machine>
```
Alerts appear in `fast.log`, e.g.
```
10/10/2026-14:22:01  [**] [1:1000002:1] LOCAL Possible port scan ... [**] {TCP} 192.168.1.20:44321 -> 192.168.1.10:80
```

## 5. Response
```bash
sudo python3 auto_block.py                     # dry run, only prints
sudo python3 auto_block.py --enforce --threshold 5
sudo iptables -L INPUT -n                      # see blocked IPs
```
Unblock with `sudo iptables -D INPUT -s <ip> -j DROP`.

## 6. Visualize
```bash
pip install matplotlib
python3 alert_summary.py /var/log/suricata/eve.json
```
For a full dashboard you can ship `eve.json` to ELK/Kibana or Grafana, but the script is enough for a quick view.

## Notes / problems I hit
- Rules didn't fire at first because `HOME_NET` was wrong.
- On VMs, set the network adapter to promiscuous mode or traffic between other hosts is not seen.
- `threshold` rules stop one scan from creating thousands of alerts.

Only run the tests against machines you own.
