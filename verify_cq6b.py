#!/usr/bin/env python3
"""Verify CQ6b client ID lengths."""
import subprocess, re

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
B = "/Users/anasuyasatapathy/Desktop/iotchallenge---2/B.pcapng"

# Find CONNECT frames for each port by searching all MQTT Connect Command frames
result = subprocess.run([TSHARK, "-r", B], capture_output=True, text=True, timeout=120)
lines = result.stdout.strip().split("\n")

# Find Connect Command lines to HiveMQ IPs
hivemq = ["18.192.151.104", "35.158.43.69", "35.158.34.213"]
connect_frames = []
for l in lines:
    if "Connect Command" in l:
        for ip in hivemq:
            if ip in l:
                m = re.match(r'\s*(\d+)', l)
                if m:
                    connect_frames.append(m.group(1))

print(f"CONNECT frames to HiveMQ: {connect_frames}")

# For each, get srcport and clientid
port_to_clientid = {}
for fn in connect_frames:
    r = subprocess.run([TSHARK, "-r", B, "-Y", f"frame.number=={fn}",
        "-T", "fields", "-e", "tcp.srcport", "-e", "mqtt.clientid"],
        capture_output=True, text=True, timeout=10)
    parts = r.stdout.strip().split("\t")
    if len(parts) >= 2:
        port_to_clientid[parts[0]] = parts[1]

print(f"\nAll HiveMQ client mappings:")
for port, cid in sorted(port_to_clientid.items()):
    print(f"  Port {port}: clientid='{cid}' (len={len(cid)})")

# Now check the 5 ports from CQ6a
target_ports = ["34779", "36777", "38207", "49877", "47753"]
print(f"\nCQ6a ports with empty retained PUBLISH:")
count_gt7 = 0
for p in target_ports:
    cid = port_to_clientid.get(p, "NOT FOUND")
    gt7 = len(cid) > 7
    if gt7:
        count_gt7 += 1
    print(f"  Port {p}: clientid='{cid}' len={len(cid)} >7? {gt7}")

print(f"\nCQ6b = {count_gt7}")
