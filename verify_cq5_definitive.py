#!/usr/bin/env python3
"""Definitive CQ5 analysis."""
import subprocess, re
from collections import defaultdict

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
B = "/Users/anasuyasatapathy/Desktop/iotchallenge---2/B.pcapng"

# Will topics and their brokers (confirmed from frame-by-frame check)
will_topics = {
    "::1":          ["university/department12/room1/temperature"],
    "5.196.78.28":  ["metaverse/room2/floor4", "hospital/facility3/area3", "metaverse/room2/room2"],
}

# Get all subscriptions with their broker
result = subprocess.run([TSHARK, "-r", B, "-Y", "mqtt.msgtype==8",
    "-T", "fields", "-e", "tcp.srcport", "-e", "mqtt.topic",
    "-e", "ip.dst", "-e", "ipv6.dst"],
    capture_output=True, text=True, timeout=60)

def mqtt_match(sub_filter, topic):
    sp = sub_filter.split("/")
    tp = topic.split("/")
    for i, s in enumerate(sp):
        if s == "#": return True
        if i >= len(tp): return False
        if s != "+" and s != tp[i]: return False
    return len(sp) == len(tp)

print("Checking every wildcard subscriber against will topics on SAME broker:\n")
matched = set()
for line in result.stdout.strip().split("\n"):
    if not line.strip(): continue
    parts = line.split("\t")
    if len(parts) < 3: continue
    port, topic = parts[0].strip(), parts[1].strip()
    broker = (parts[3].strip() if len(parts) > 3 and parts[3].strip() else parts[2].strip())
    if not broker: broker = parts[2].strip()

    if "+" not in topic and "#" not in topic:
        continue  # not wildcard

    wills = will_topics.get(broker, [])
    for wt in wills:
        if mqtt_match(topic, wt):
            print(f"  Port {port} @ broker {broker}: '{topic}' MATCHES will '{wt}'")
            matched.add(port)

print(f"\nUnique subscribers: {sorted(matched)}")
print(f"\nCQ5 = {len(matched)}")
