#!/usr/bin/env python3
"""
CQ5 Complete: How many MQTT subscribers receive a last will message
via a wildcard subscription, across ALL brokers.
"""
import subprocess, re

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
B = "/Users/anasuyasatapathy/Desktop/iotchallenge---2/B.pcapng"

# ---- Step 1: Get all lines ----
result = subprocess.run([TSHARK, "-r", B], capture_output=True, text=True, timeout=120)
all_lines = result.stdout.strip().split("\n")

# ---- Step 2: Map each TCP srcport -> broker IP (from SYN to port 1883) ----
port_broker = {}
for l in all_lines:
    m = re.search(r'(\S+)\s*→\s*(\S+)\s+TCP.*?(\d+) → 1883 \[SYN\]', l)
    if m:
        src_ip = m.group(1)
        dst_ip = m.group(2)
        port   = m.group(3)
        port_broker[port] = dst_ip

print("Port → Broker mapping (all MQTT clients):")
for p, b in sorted(port_broker.items()):
    print(f"  {p} → {b}")

# ---- Step 3: Will clients ----
will_clients = {
    "38083": ("university/department12/room1/temperature", "::1"),
    "56285": ("metaverse/room2/floor4",  "5.196.78.28"),
    "53485": ("hospital/facility3/area3","5.196.78.28"),
    "42665": ("metaverse/room2/room2",   "5.196.78.28"),
}
# Group wills by broker
from collections import defaultdict
wills_by_broker = defaultdict(list)
for port, (topic, broker) in will_clients.items():
    wills_by_broker[broker].append(topic)

print("\nWills by broker:")
for broker, topics in wills_by_broker.items():
    print(f"  {broker}: {topics}")

# ---- Step 4: Get all subscriptions with port->broker ----
result2 = subprocess.run([TSHARK, "-r", B, "-Y", "mqtt.msgtype==8",
    "-T", "fields", "-e", "tcp.srcport", "-e", "mqtt.topic"],
    capture_output=True, text=True, timeout=60)

subs = defaultdict(list)
for line in result2.stdout.strip().split("\n"):
    if not line.strip():
        continue
    parts = line.split("\t")
    if len(parts) >= 2:
        subs[parts[0]].append(parts[1])

def mqtt_match(sub_filter, topic):
    sp = sub_filter.split("/")
    tp = topic.split("/")
    for i, s in enumerate(sp):
        if s == "#": return True
        if i >= len(tp): return False
        if s != "+" and s != tp[i]: return False
    return len(sp) == len(tp)

# ---- Step 5: For each subscriber, check if on same broker as a will,
#              has wildcard, and matches that will topic ----
print("\n--- Checking all subscribers ---")
matched_subscribers = set()
for sub_port, topics in sorted(subs.items()):
    sub_broker = port_broker.get(sub_port, "unknown")
    # Skip if not a will broker
    if sub_broker not in wills_by_broker:
        continue
    will_topics_for_broker = wills_by_broker[sub_broker]
    for t in topics:
        if "+" not in t and "#" not in t:
            continue  # not wildcard
        for wt in will_topics_for_broker:
            if mqtt_match(t, wt):
                print(f"  Sub port={sub_port} broker={sub_broker} filter='{t}' matches will='{wt}'")
                matched_subscribers.add(sub_port)

print(f"\nUnique subscribers matching via wildcard: {sorted(matched_subscribers)}")
print(f"\nCQ5 = {len(matched_subscribers)}")
