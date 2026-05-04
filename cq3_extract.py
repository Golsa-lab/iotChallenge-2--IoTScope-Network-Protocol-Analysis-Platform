#!/usr/bin/env python3
"""Extract observe notification payloads using tshark JSON output."""
import subprocess, json

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
FILE_A = "/Users/anasuyasatapathy/Desktop/iotchallenge---2/A.pcapng"

# Get observe notifications as JSON
cmd = [TSHARK, "-r", FILE_A, "-Y", 
       "coap.token==89b9 && coap.opt.observe && coap.code==69",
       "-T", "ek", "-e", "frame.number", "-e", "coap.mid", 
       "-e", "coap.opt.observe", "-e", "coap.type"]
result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

# Also get raw bytes to find payload
cmd2 = [TSHARK, "-r", FILE_A, "-Y",
        "coap.token==89b9 && coap.opt.observe && coap.code==69",
        "-T", "fields", "-e", "frame.number", "-e", "coap.mid",
        "-e", "coap.opt.observe", "-e", "coap.type",
        "-E", "separator=|"]
result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=60)

# Parse and deduplicate by MID
seen_mids = set()
unique_notifications = []
for line in result2.stdout.strip().split('\n'):
    parts = line.split('|')
    if len(parts) >= 4:
        frame, mid, obs, msg_type = parts[0], parts[1], parts[2], parts[3]
        if mid not in seen_mids:
            seen_mids.add(mid)
            unique_notifications.append({'frame': frame, 'mid': mid, 'obs': obs, 'type': msg_type})

print(f"Unique notifications (by MID): {len(unique_notifications)}")

# Now get payload for each unique notification frame
for n in unique_notifications:
    cmd3 = [TSHARK, "-r", FILE_A, "-Y", f"frame.number=={n['frame']}",
            "-T", "fields", "-e", "coap.payload_raw", "-e", "data.data_raw"]
    r = subprocess.run(cmd3, capture_output=True, text=True, timeout=30)
    # Try to decode the payload
    raw = r.stdout.strip()
    # Also get via -V to see the text
    cmd4 = [TSHARK, "-r", FILE_A, "-Y", f"frame.number=={n['frame']}",
            "-V"]
    r4 = subprocess.run(cmd4, capture_output=True, text=True, timeout=30)
    # Find the JSON payload line
    payload = ""
    for vline in r4.stdout.split('\n'):
        if '"value"' in vline:
            payload = vline.strip()
            break
    if not payload:
        # Look for the whole JSON
        for vline in r4.stdout.split('\n'):
            if 'JavaScript Object Notation' in vline or '[{"name"' in vline:
                payload = vline.strip()
                break
    
    # Try to find value from verbose output
    value = ""
    for vline in r4.stdout.split('\n'):
        if '"value":' in vline:
            # Extract the value
            import re
            m = re.search(r'"value":\s*"([^"]*)"', vline)
            if m:
                value = m.group(1)
                break
    
    if not value:
        # Search in full verbose output for the JSON payload
        text = r4.stdout
        import re
        matches = re.findall(r'"value":\s*"([^"]*)"', text)
        if matches:
            value = matches[0]
    
    n['value'] = value
    print(f"  Frame {n['frame']}: MID={n['mid']}, obs={n['obs']}, type={n['type']}, value={value}")

# CQ3a
print(f"\nCQ3a) Number of separate observe notifications: {len(unique_notifications)}")

# CQ3b: useless = same value as previous
useless = 0
prev_value = None
for n in unique_notifications:
    if prev_value is not None and n['value'] == prev_value and n['value'] != "":
        useless += 1
        print(f"  USELESS: Frame {n['frame']}, value={n['value']}")
    prev_value = n['value']

print(f"\nCQ3b) Useless notifications: {useless}")
