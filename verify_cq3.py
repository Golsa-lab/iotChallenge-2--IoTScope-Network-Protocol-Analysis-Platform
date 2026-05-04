#!/usr/bin/env python3
"""Re-verify CQ3a, CQ3b, CQ5, CQ6b using scapy for reliable parsing."""
import subprocess, re

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
A = "/Users/anasuyasatapathy/Desktop/iotchallenge---2/A.pcapng"
B = "/Users/anasuyasatapathy/Desktop/iotchallenge---2/B.pcapng"

def tshark_lines(pcap, display_filter, fields):
    """Run tshark and return list of tab-separated field rows."""
    cmd = [TSHARK, "-r", pcap, "-Y", display_filter, "-T", "fields"] + \
          [x for f in fields for x in ("-e", f)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    lines = [l for l in result.stdout.strip().split("\n") if l.strip()]
    return lines

# =====================================================================
# Use frame-by-frame approach since broad display filters seem broken
# Extract ALL packets to a text dump, then parse with Python
# =====================================================================

print("=" * 60)
print("Extracting all packets from A.pcapng (text summary)...")
print("=" * 60)

# Get all CoAP packets to/from coap.me by grepping the full listing
result = subprocess.run(
    [TSHARK, "-r", A],
    capture_output=True, text=True, timeout=120
)
all_lines = result.stdout.strip().split("\n")

# Find CoAP DELETE to coap.me
coap_me_lines = [l for l in all_lines if "134.102.218.18" in l]
print(f"Total packets involving 134.102.218.18: {len(coap_me_lines)}")

# Separate requests (to) and responses (from)
to_coap = [l for l in coap_me_lines if "→ 134.102.218.18" in l or "-> 134.102.218.18" in l]
from_coap = [l for l in coap_me_lines if "134.102.218.18 →" in l or "134.102.218.18 ->" in l]
print(f"  To coap.me: {len(to_coap)}")
print(f"  From coap.me: {len(from_coap)}")

# Find DELETE requests
delete_reqs = [l for l in to_coap if "DELETE" in l]
print(f"  DELETE requests: {len(delete_reqs)}")

# Count NON DELETE
non_delete = [l for l in delete_reqs if "NON" in l]
print(f"  NON DELETE requests: {len(non_delete)}")

# =====================================================================
# CQ3: Observe notifications
# =====================================================================
print("\n" + "=" * 60)
print("CQ3: Observe Notifications from coap.me")
print("=" * 60)

# Look for Observe in responses from coap.me
observe_lines = [l for l in from_coap if "Observe" in l.lower() or "observe" in l.lower()]
print(f"Lines mentioning 'observe' from coap.me: {len(observe_lines)}")

# Actually, the text summary may not show "observe" - let's look for 
# response patterns. Observe notifications are responses with content.
# Let me try a different approach - use frame numbers

# Get frame numbers of all packets from coap.me
frame_nums_from = []
for l in from_coap:
    m = re.match(r'\s*(\d+)', l)
    if m:
        frame_nums_from.append(m.group(1))

print(f"Frame numbers from coap.me: {len(frame_nums_from)}")

# Now extract detailed info for each frame one by one
# To check observe option, use -V on each frame
# But that's slow for 200+ frames. Let's try a smarter approach.

# Use the frame number filter approach since individual filters work
print("\nExtracting observe info per-frame (this may take a moment)...")

observe_frames = []
for fn in frame_nums_from:
    cmd = [TSHARK, "-r", A, "-Y", f"frame.number=={fn}", 
           "-T", "fields", "-e", "frame.number", "-e", "coap.mid",
           "-e", "coap.type", "-e", "coap.code", "-e", "coap.opt.observe"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    parts = r.stdout.strip().split("\t")
    if len(parts) >= 5 and parts[4]:  # observe field is non-empty
        observe_frames.append(parts)

print(f"\nFrames with Observe option from coap.me: {len(observe_frames)}")
for f in observe_frames:
    print(f"  Frame={f[0]}, MID={f[1]}, Type={f[2]}, Code={f[3]}, Observe={f[4]}")

# Unique by MID
mids = set()
unique_observe = []
for f in observe_frames:
    mid = f[1]
    if mid not in mids:
        mids.add(mid)
        unique_observe.append(f)

print(f"\nUnique observe notifications (by MID): {len(unique_observe)}")
for f in unique_observe:
    type_name = {0:"CON", 1:"NON", 2:"ACK", 3:"RST"}.get(int(f[2]), f[2])
    print(f"  MID={f[1]}, Type={type_name}, Code={f[3]}, Observe={f[4]}")

# CQ3b: Check which CON notifications were ACKed
con_mids = [f[1] for f in unique_observe if f[2] == "0"]  # type 0 = CON
print(f"\nCON notifications: {len(con_mids)} MIDs: {con_mids}")

# Check for ACKs sent TO coap.me matching these MIDs
acked_mids = set()
for fn in [re.match(r'\s*(\d+)', l).group(1) for l in to_coap if re.match(r'\s*(\d+)', l)]:
    cmd = [TSHARK, "-r", A, "-Y", f"frame.number=={fn}",
           "-T", "fields", "-e", "coap.mid", "-e", "coap.type"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    parts = r.stdout.strip().split("\t")
    if len(parts) >= 2 and parts[1] == "2":  # type 2 = ACK
        acked_mids.add(parts[0])

unacked_con = [m for m in con_mids if m not in acked_mids]
print(f"ACKed MIDs to coap.me: {acked_mids}")
print(f"Un-ACKed CON MIDs: {unacked_con}")
print(f"\nCQ3a = {len(unique_observe)}")
print(f"CQ3b (useless/un-ACKed CON) = {len(unacked_con)}")
