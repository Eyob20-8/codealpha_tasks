#!/bin/bash
# Run from ANOTHER machine/VM against your own test server to trigger the rules.
# Never run this against systems you don't own.
TARGET=${1:?usage: ./attack_tests.sh <target-ip>}

echo "[1] ping";              ping -c 2 $TARGET
echo "[2] port scan";         nmap -sS -p 1-200 $TARGET
echo "[3] ssh attempts";      for i in 1 2 3 4 5 6 7; do nc -w1 $TARGET 22 </dev/null; done
echo "[4] sqli in url";       curl -s "http://$TARGET/?id=1%20UNION%20SELECT%201,2" >/dev/null
echo "[5] traversal";         curl -s --path-as-is "http://$TARGET/../../etc/passwd" >/dev/null
echo "[6] xss";               curl -s "http://$TARGET/?q=<script>alert(1)</script>" >/dev/null
echo "[7] scanner UA";        curl -s -A "sqlmap/1.7" "http://$TARGET/" >/dev/null
echo "done - check /var/log/suricata/fast.log"
