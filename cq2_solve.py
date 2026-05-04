#!/usr/bin/env python3
"""CQ2: Resources with equal unique unsuccessful CON POST and PUT."""
import subprocess, collections

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
FILE_A = "/Users/anasuyasatapathy/Desktop/iotchallenge---2/A.pcapng"

def run(filt, fields):
    cmd = [TSHARK, "-r", FILE_A, "-Y", filt, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    cmd += ["-E", "separator=|"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return [l for l in r.stdout.strip().split('\n') if l.strip()]

# Get all CON POST/PUT to local server (127.0.0.1)
for method, code in [("POST", "2"), ("PUT", "3")]:
    lines = run(f"coap.type==0 && coap.code=={code} && ip.dst==127.0.0.1",
        ["frame.number", "coap.mid", "coap.opt.uri_path_recon"])
    print(f"\nCON {method} to local server: {len(lines)}")
    
    # For each, check response
    unsuccessful = collections.defaultdict(set)
    
    for line in lines:
        parts = line.split('|')
        frame, mid, uri = parts[0], parts[1], parts[2] if len(parts) > 2 else ''
        
        # Check ACK response
        resp_lines = run(f"coap.type==2 && coap.mid=={mid} && ip.src==127.0.0.1",
            ["coap.code"])
        
        if resp_lines:
            resp_code = resp_lines[0].strip()
            # Decode: in tshark numeric format
            # 128=4.00, 129=4.01, ..., 132=4.04, 133=4.05, etc.
            # 160=5.00
            try:
                code_num = int(resp_code)
                code_class = code_num >> 5  # top 3 bits = class
                code_detail = code_num & 0x1F  # bottom 5 bits = detail
                if code_class >= 4:  # 4.xx or 5.xx = unsuccessful
                    unsuccessful[uri].add(mid)
                    print(f"  Frame {frame}: MID={mid}, uri={uri}, resp={code_class}.{code_detail:02d} UNSUCCESSFUL")
            except:
                pass
    
    if method == "POST":
        post_unsuccessful = dict(unsuccessful)
    else:
        put_unsuccessful = dict(unsuccessful)

print("\n\nSummary:")
print("Resources with unsuccessful CON POST:")
for res, mids in sorted(post_unsuccessful.items()):
    print(f"  {res}: {len(mids)} unique")

print("\nResources with unsuccessful CON PUT:")
for res, mids in sorted(put_unsuccessful.items()):
    print(f"  {res}: {len(mids)} unique")

all_res = set(list(post_unsuccessful.keys()) + list(put_unsuccessful.keys()))
matching = 0
for res in sorted(all_res):
    x = len(post_unsuccessful.get(res, set()))
    y = len(put_unsuccessful.get(res, set()))
    tag = " *** MATCH ***" if x == y and x > 0 else ""
    print(f"  {res}: POST={x}, PUT={y}{tag}")
    if x == y and x > 0:
        matching += 1

print(f"\nCQ2) Answer: {matching}")
