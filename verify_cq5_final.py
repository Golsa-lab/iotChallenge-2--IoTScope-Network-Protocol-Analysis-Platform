#!/usr/bin/env python3
"""Final CQ5: check which LOCAL wildcard subscribers match ANY will topic."""
import subprocess, re

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
B = "/Users/anasuyasatapathy/Desktop/iotchallenge---2/B.pcapng"

# Get all lines to determine which port connects where
result = subprocess.run([TSHARK, "-r", B], capture_output=True, text=True, timeout=120)
all_lines = result.stdout.strip().split("\n")

# Map port -> broker IP from SYN packets to port 1883
port_broker = {}
for l in all_lines:
    m = re.search(r'(\d+) → 1883 \[SYN\]', l)
    if m:
        port = m.group(1)
        # Find IP
        ip_m = re.search(r'([\d.]+|::1)\s*→\s*([\d.]+|::1)', l)
        if ip_m:
            port_broker[port] = ip_m.group(2)

# All will topics (from all 4 will clients, regardless of broker)
will_topics = [
    "university/department12/room1/temperature",  # port 38083 -> local
    "metaverse/room2/floor4",                      # port 56285 -> 5.196.78.28
    "hospital/facility3/area3",                    # port 53485 -> 5.196.78.28
    "metaverse/room2/room2",                       # port 42665 -> 5.196.78.28
]

# Get subscriptions
result2 = subprocess.run([TSHARK, "-r", B, "-Y", "mqtt.msgtype==8",
    "-T", "fields", "-e", "tcp.srcport", "-e", "mqtt.topic"],
    capture_output=True, text=True, timeout=60)

subs = {}
for line in result2.stdout.strip().split("\n"):
    if not line.strip():
        continue
    parts = line.split("\t")
    if len(parts) >= 2:
        port = parts[0]
        topic = parts[1]
        if port not in subs:
            subs[port] = []
        subs[port].append(topic)

def mqtt_match(sub_filter, topic):
    sub_parts = sub_filter.split("/")
    topic_parts = topic.split("/")
    for i, sp in enumerate(sub_parts):
        if sp == "#":
            return True
        if i >= len(topic_parts):
            return False
        if sp == "+":
            continue
        if sp != topic_parts[i]:
            return False
    return len(sub_parts) == len(topic_parts)

# For each subscriber port, determine which broker it's on
print("All subscriber ports and their brokers:")
local_wildcard_match = set()
for port, topics in sorted(subs.items()):
    broker = port_broker.get(port, "unknown")
    is_local = (broker == "::1" or broker == "127.0.0.1")
    wildcard_topics = [t for t in topics if "+" in t or "#" in t]
    if not wildcard_topics:
        continue
    
    # Check if any wildcard topic matches any will topic
    for wt in wildcard_topics:
        for will_t in will_topics:
            if mqtt_match(wt, will_t):
                status = "LOCAL" if is_local else f"EXTERNAL({broker})"
                print(f"  Port {port} [{status}]: '{wt}' matches will '{will_t}'")
                if is_local:
                    local_wildcard_match.add(port)

print(f"\nLocal wildcard subscribers matching a will: {sorted(local_wildcard_match)}")
print(f"Count = {len(local_wildcard_match)}")

# But wait - the question says "receive a last will message"
# A subscriber on the local broker can only receive wills published by the local broker
# A subscriber on HiveMQ can only receive wills published by HiveMQ
# Unless there's bridging

# Will published by local broker: university/department12/room1/temperature
# Wills published by 5.196.78.28: metaverse/room2/floor4, hospital/facility3/area3, metaverse/room2/room2

# Check: do local subscribers with metaverse/# actually RECEIVE the will?
# The will for metaverse topics is published by 5.196.78.28, not local broker
# So local subscribers would NOT receive those... UNLESS there's bridging

# Let's check if there's any evidence of bridging (messages from external being 
# forwarded to local subscribers)
print("\n--- Checking for bridge: PUBLISH from local broker to local subscribers ---")
# Look for PUBLISH from local broker (srcport 1883, ::1) with metaverse topics
metaverse_local = [l for l in all_lines if "metaverse" in l.lower() and "::1" in l]
print(f"Lines with 'metaverse' and '::1': {len(metaverse_local)}")
for l in metaverse_local[:10]:
    print(f"  {l.strip()[:120]}")

university_local = [l for l in all_lines if "university" in l.lower() and "::1" in l]
print(f"\nLines with 'university' and '::1': {len(university_local)}")
for l in university_local[:10]:
    print(f"  {l.strip()[:120]}")
