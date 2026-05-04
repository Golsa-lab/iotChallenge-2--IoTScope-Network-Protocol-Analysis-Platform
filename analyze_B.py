#!/usr/bin/env python3
"""Analyze B.pcapng for CQ5-CQ7 and CQ8."""
import subprocess, collections, re

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
FILE_B = "/Users/anasuyasatapathy/Desktop/iotchallenge---2/B.pcapng"
FILE_A = "/Users/anasuyasatapathy/Desktop/iotchallenge---2/A.pcapng"

# HiveMQ IPs from DNS
HIVEMQ_IPS = {"18.192.151.104", "35.158.43.69", "35.158.34.213"}

def run_tshark(pcap, filt, fields):
    cmd = [TSHARK, "-r", pcap, "-Y", filt, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    cmd += ["-E", "separator=|"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    lines = [l for l in r.stdout.strip().split('\n') if l.strip()]
    return lines

###############################################################################
# CQ6a: Clients that sent retain=1 with empty payload to HiveMQ
###############################################################################
print("=" * 70)
print("CQ6a: MQTT clients erasing retained values on HiveMQ")
print("=" * 70)

# Get all retained PUBLISH messages, then filter for empty payload and HiveMQ dest
lines = run_tshark(FILE_B, "mqtt.msgtype==3 && mqtt.retain==1",
    ["frame.number", "mqtt.topic", "mqtt.msg", "tcp.srcport", "ip.dst", "ipv6.dst", "tcp.dstport"])

erase_clients = set()  # TCP srcports that sent empty retained to HiveMQ
erase_details = []

for line in lines:
    parts = line.split('|')
    if len(parts) < 7:
        continue
    frame, topic, msg, srcport, dst_ip, dst_ipv6, dstport = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
    
    # Check if going to HiveMQ
    is_hivemq = dst_ip in HIVEMQ_IPS
    
    # Empty payload = msg field is empty
    if is_hivemq and msg.strip() == '':
        erase_clients.add(srcport)
        erase_details.append(f"  Frame {frame}: topic={topic}, srcport={srcport}, dst={dst_ip}")

print(f"\nRetained PUBLISH with empty payload to HiveMQ:")
for d in erase_details:
    print(d)

# Now map srcport to clientid
# Get CONNECT messages to HiveMQ with client IDs
connect_lines = run_tshark(FILE_B, "mqtt.msgtype==1",
    ["frame.number", "mqtt.clientid", "tcp.srcport", "ip.dst", "tcp.dstport", "mqtt.clientid_len"])

port_to_client = {}
for line in connect_lines:
    parts = line.split('|')
    if len(parts) >= 4:
        frame, clientid, srcport, dst_ip = parts[0], parts[1], parts[2], parts[3]
        # Multiple values might be comma-separated
        for sp in srcport.split(','):
            port_to_client[sp.strip()] = (clientid, dst_ip, parts[5] if len(parts) > 5 else '')

unique_clients = set()
for port in erase_clients:
    if port in port_to_client:
        cid, dst, cid_len = port_to_client[port]
        unique_clients.add(cid)
        print(f"  Port {port} -> client '{cid}' (len={cid_len}), dst={dst}")
    else:
        print(f"  Port {port} -> UNKNOWN client")

print(f"\nCQ6a) Different MQTT clients erasing retained: {len(unique_clients)}")
print(f"  Clients: {unique_clients}")

###############################################################################
# CQ6b: Of those clients, how many have client ID > 7 bytes?
###############################################################################
print("\n" + "=" * 70)
print("CQ6b: Clients from CQ6a with client ID > 7 bytes")
print("=" * 70)

long_id_count = 0
for cid in unique_clients:
    if len(cid) > 7:
        long_id_count += 1
        print(f"  '{cid}' length={len(cid)} > 7")
    else:
        print(f"  '{cid}' length={len(cid)} <= 7")

print(f"\nCQ6b) Answer: {long_id_count}")

###############################################################################
# CQ7: SUBSCRIBE requests to local broker with >= 2 wildcards in topic
###############################################################################
print("\n" + "=" * 70)
print("CQ7: SUBSCRIBE to local broker with >= 2 wildcards")
print("=" * 70)

# Local broker = ::1:1883 or 127.0.0.1:1883
sub_lines = run_tshark(FILE_B, 'mqtt.msgtype==8',
    ["frame.number", "mqtt.topic", "ip.dst", "ipv6.dst", "tcp.dstport"])

wildcard_2_count = 0
for line in sub_lines:
    parts = line.split('|')
    if len(parts) < 5:
        continue
    frame, topic, dst_ip, dst_ipv6, dstport = parts[0], parts[1], parts[2], parts[3], parts[4]
    
    # Check if local broker
    is_local = (dst_ipv6 == '::1' or dst_ip == '127.0.0.1') and dstport == '1883'
    
    if is_local:
        # Count wildcards (+ and #) in topic
        # Topics might be comma-separated if multiple in one SUBSCRIBE
        topics = topic.split(',')
        for t in topics:
            t = t.strip()
            wc_count = t.count('+') + t.count('#')
            if wc_count >= 2:
                wildcard_2_count += 1
                print(f"  Frame {frame}: topic='{t}' wildcards={wc_count}")

print(f"\nCQ7) Answer: {wildcard_2_count}")

###############################################################################
# CQ8: Topic layers histogram for local broker PUBLISH
###############################################################################
print("\n" + "=" * 70)
print("CQ8: Topic layers for local broker PUBLISH messages")
print("=" * 70)

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

for label, pcap in [("A.pcapng", FILE_A), ("B.pcapng", FILE_B)]:
    # PUBLISH to local broker: dstport=1883, dst=::1 or 127.0.0.1
    # For A.pcapng, MQTT might be on different port - check
    pub_lines = run_tshark(pcap, 'mqtt.msgtype==3 && tcp.dstport==1883',
        ["frame.number", "mqtt.topic", "ip.dst", "ipv6.dst"])
    
    # Filter to local broker only
    local_topics = []
    for line in pub_lines:
        parts = line.split('|')
        if len(parts) < 4:
            continue
        frame, topic, dst_ip, dst_ipv6 = parts[0], parts[1], parts[2], parts[3]
        
        is_local = (dst_ipv6 == '::1' or dst_ip == '127.0.0.1' or dst_ip == '')
        if is_local and dst_ipv6 == '::1':
            # Topics might be comma-separated (multiple PUBLISH in one TCP segment)
            topics = topic.split(',')
            for t in topics:
                t = t.strip()
                if t:
                    local_topics.append(t)
    
    # Count layers (number of / + 1)
    layer_counts = collections.Counter()
    for t in local_topics:
        layers = len(t.split('/'))
        layer_counts[layers] += 1
    
    print(f"\n{label}: Total PUBLISH to local broker = {len(local_topics)}")
    print(f"  Layer distribution: {dict(sorted(layer_counts.items()))}")

# Generate histogram
for label, pcap in [("A.pcapng", FILE_A), ("B.pcapng", FILE_B)]:
    pub_lines = run_tshark(pcap, 'mqtt.msgtype==3 && tcp.dstport==1883',
        ["frame.number", "mqtt.topic", "ip.dst", "ipv6.dst"])
    
    local_topics = []
    for line in pub_lines:
        parts = line.split('|')
        if len(parts) < 4:
            continue
        frame, topic, dst_ip, dst_ipv6 = parts[0], parts[1], parts[2], parts[3]
        is_local = (dst_ipv6 == '::1' or dst_ip == '127.0.0.1')
        if is_local:
            topics = topic.split(',')
            for t in topics:
                t = t.strip()
                if t:
                    local_topics.append(t)
    
    layer_counts = collections.Counter()
    for t in local_topics:
        layers = len(t.split('/'))
        layer_counts[layers] += 1
    
    if label == "A.pcapng":
        a_counts = dict(sorted(layer_counts.items()))
        a_total = len(local_topics)
    else:
        b_counts = dict(sorted(layer_counts.items()))
        b_total = len(local_topics)

print(f"\nCQ8a) Total PUBLISH to local broker in A.pcapng: {a_total}")
print(f"CQ8b) Total PUBLISH to local broker in B.pcapng: {b_total}")

# Plot
all_layers = sorted(set(list(a_counts.keys()) + list(b_counts.keys())))
x = range(len(all_layers))
width = 0.35

fig, ax = plt.subplots(figsize=(10, 6))
bars1 = ax.bar([i - width/2 for i in x], [a_counts.get(l, 0) for l in all_layers], width, label='A.pcapng', color='steelblue')
bars2 = ax.bar([i + width/2 for i in x], [b_counts.get(l, 0) for l in all_layers], width, label='B.pcapng', color='darkorange')

ax.set_xlabel('Number of topic layers')
ax.set_ylabel('Number of PUBLISH messages')
ax.set_title('Distribution of MQTT topic depth for local broker')
ax.set_xticks(list(x))
ax.set_xticklabels(all_layers)
ax.legend()
ax.bar_label(bars1, padding=2)
ax.bar_label(bars2, padding=2)

plt.tight_layout()
plt.savefig('/Users/anasuyasatapathy/Desktop/iotchallenge---2/cq8_histogram.png', dpi=150)
print("\nHistogram saved to cq8_histogram.png")
