#!/usr/bin/env python3
"""Generate CQ8 histogram for both A.pcapng and B.pcapng."""
import subprocess, collections
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
FILE_A = "/Users/anasuyasatapathy/Desktop/iotchallenge---2/A.pcapng"
FILE_B = "/Users/anasuyasatapathy/Desktop/iotchallenge---2/B.pcapng"

def get_topic_layers(pcap, local_filter):
    cmd = [TSHARK, "-r", pcap, "-Y", f"mqtt.msgtype==3 && tcp.dstport==1883 && {local_filter}",
           "-T", "fields", "-e", "mqtt.topic", "-E", "separator=|"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    topics = []
    for line in r.stdout.strip().split('\n'):
        if not line.strip():
            continue
        # Topics can be comma-separated (multiple in one TCP segment)
        for t in line.split(','):
            t = t.strip()
            if t:
                topics.append(t)
    
    layer_counts = collections.Counter()
    for t in topics:
        layers = len(t.split('/'))
        layer_counts[layers] += 1
    return len(topics), dict(sorted(layer_counts.items()))

# A.pcapng: local broker is 127.0.0.1
a_total, a_counts = get_topic_layers(FILE_A, "ip.dst==127.0.0.1")
# B.pcapng: local broker is ::1
b_total, b_counts = get_topic_layers(FILE_B, "ipv6.dst==::1")

print(f"A.pcapng: {a_total} PUBLISH messages, layers: {a_counts}")
print(f"B.pcapng: {b_total} PUBLISH messages, layers: {b_counts}")
print(f"\nCQ8a) A.pcapng total: {a_total}")
print(f"CQ8b) B.pcapng total: {b_total}")

# Plot
all_layers = sorted(set(list(a_counts.keys()) + list(b_counts.keys())))
x = range(len(all_layers))
width = 0.35

fig, ax = plt.subplots(figsize=(10, 6))
a_vals = [a_counts.get(l, 0) for l in all_layers]
b_vals = [b_counts.get(l, 0) for l in all_layers]

bars1 = ax.bar([i - width/2 for i in x], a_vals, width, label='A.pcapng', color='steelblue')
bars2 = ax.bar([i + width/2 for i in x], b_vals, width, label='B.pcapng', color='darkorange')

ax.set_xlabel('Number of topic layers')
ax.set_ylabel('Number of PUBLISH messages')
ax.set_title('Distribution of MQTT topic depth for local broker')
ax.set_xticks(list(x))
ax.set_xticklabels(all_layers)
ax.legend()
ax.bar_label(bars1, padding=2)
ax.bar_label(bars2, padding=2)

plt.tight_layout()
plt.savefig('/Users/anasuyasatapathy/Desktop/iotchallenge---2/cq8_histogram.png', dpi=150, bbox_inches='tight')
print("\nHistogram saved to cq8_histogram.png")
