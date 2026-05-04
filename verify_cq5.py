#!/usr/bin/env python3
"""Verify CQ5: which wildcard subscribers receive will messages."""
import subprocess, re

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
B = "/Users/anasuyasatapathy/Desktop/iotchallenge---2/B.pcapng"

# Get all subscriptions
result = subprocess.run([TSHARK, "-r", B, "-Y", "mqtt.msgtype==8 and tcp.dstport==1883",
    "-T", "fields", "-e", "tcp.srcport", "-e", "mqtt.topic"],
    capture_output=True, text=True, timeout=60)

# Parse subscriptions - each line may have multiple topics (comma-separated)
subs = {}  # port -> [topics]
for line in result.stdout.strip().split("\n"):
    if not line.strip():
        continue
    parts = line.split("\t")
    if len(parts) >= 2:
        port = parts[0]
        topic = parts[1]
        if port not in subs:
            subs[port] = []
        subs[port].append(topic)

# Will topics
will_topics = [
    ("38083", "university/department12/room1/temperature"),
    ("56285", "metaverse/room2/floor4"),
    ("53485", "hospital/facility3/area3"),
    ("42665", "metaverse/room2/room2"),
]

def mqtt_match(sub_filter, topic):
    """Check if MQTT subscription filter matches a topic."""
    sub_parts = sub_filter.split("/")
    topic_parts = topic.split("/")
    
    i = 0
    for i, sp in enumerate(sub_parts):
        if sp == "#":
            return True  # # matches everything after
        if i >= len(topic_parts):
            return False
        if sp == "+":
            continue  # + matches exactly one level
        if sp != topic_parts[i]:
            return False
    
    # Must have consumed all topic parts
    return i == len(sub_parts) - 1 and len(sub_parts) == len(topic_parts)

# Check which wildcard subscribers match each will topic
print("Will topic matching:\n")
all_matching_ports = set()

for will_port, will_topic in will_topics:
    print(f"Will topic: {will_topic} (client port {will_port})")
    for port, topics in subs.items():
        if port == will_port:
            continue  # skip self
        for t in topics:
            if ("+" in t or "#" in t) and mqtt_match(t, will_topic):
                print(f"  MATCH: port {port} subscribed to '{t}'")
                all_matching_ports.add(port)
    print()

print(f"Unique wildcard subscriber ports that received a will: {sorted(all_matching_ports)}")
print(f"CQ5 = {len(all_matching_ports)}")

# Also check for exact matches (non-wildcard) for completeness
print("\n--- Also checking exact (non-wildcard) matches ---")
for will_port, will_topic in will_topics:
    for port, topics in subs.items():
        if port == will_port:
            continue
        for t in topics:
            if "+" not in t and "#" not in t and t == will_topic:
                print(f"  EXACT match: port {port} subscribed to '{t}' for will '{will_topic}'")
