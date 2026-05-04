#!/usr/bin/env python3
"""
Complete Analysis Script for IoT Challenge #2
Anasuya Satapathy (11175090)
Uses tshark for packet analysis.
"""

import subprocess
import json
import collections
import csv
import io

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
FILE_A = "/Users/anasuyasatapathy/Desktop/iotchallenge---2/A.pcapng"
FILE_B = "/Users/anasuyasatpathy/Desktop/iotchallenge---2/B.pcapng"

def run_tshark(pcap, display_filter, fields, extra_args=None):
    """Run tshark and return list of dicts."""
    cmd = [TSHARK, "-r", pcap, "-Y", display_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    cmd += ["-E", "separator=|", "-E", "header=y"]
    if extra_args:
        cmd += extra_args
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"tshark error: {result.stderr[:500]}")
        return []
    
    lines = result.stdout.strip().split('\n')
    if len(lines) < 2:
        return []
    
    headers = lines[0].split('|')
    # Clean header names
    headers = [h.strip().replace('.', '_') for h in headers]
    rows = []
    for line in lines[1:]:
        vals = line.split('|')
        row = {}
        for i, h in enumerate(headers):
            row[h] = vals[i] if i < len(vals) else ''
        rows.append(row)
    return rows

def run_tshark_count(pcap, display_filter):
    """Count packets matching filter."""
    cmd = [TSHARK, "-r", pcap, "-Y", display_filter, "-T", "fields", "-e", "frame.number"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    lines = [l for l in result.stdout.strip().split('\n') if l.strip()]
    return len(lines)

def run_tshark_raw(pcap, display_filter, fields, extra_args=None):
    """Run tshark and return raw stdout."""
    cmd = [TSHARK, "-r", pcap, "-Y", display_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    cmd += ["-E", "separator=|"]
    if extra_args:
        cmd += extra_args
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout.strip()

###############################################################################
# CQ1
###############################################################################
def solve_cq1():
    print("=" * 70)
    print("CQ1: NON DELETE requests to coap.me with successful response")
    print("=" * 70)
    
    # Step 1: Find all NON (type=1) DELETE (code=4) requests
    # Check destination: coap.me = 134.102.218.18 or check uri-host option
    
    raw = run_tshark_raw(FILE_A, "coap.type==1 && coap.code==4",
        ["frame.number", "coap.mid", "coap.token", "ip.dst", "ip.src", 
         "coap.opt.uri_host", "coap.opt.uri_path_recon"])
    
    print("\nAll NON DELETE requests:")
    print(raw)
    
    if not raw:
        print("No NON DELETE requests found. Trying alternate filter...")
        # Maybe code is displayed differently
        raw = run_tshark_raw(FILE_A, "coap.type==1",
            ["frame.number", "coap.mid", "coap.code", "ip.dst", "coap.opt.uri_host"])
        print("All NON requests:")
        print(raw[:2000])
    
    # Parse NON DELETE requests to coap.me
    lines = raw.split('\n') if raw else []
    coap_me_requests = []
    
    for line in lines:
        parts = line.split('|')
        if len(parts) >= 4:
            frame, mid, token, dst = parts[0], parts[1], parts[2], parts[3]
            uri_host = parts[5] if len(parts) > 5 else ''
            uri_path = parts[6] if len(parts) > 6 else ''
            
            # Check if to coap.me
            if 'coap.me' in uri_host or dst == '134.102.218.18':
                coap_me_requests.append({
                    'frame': frame, 'mid': mid, 'token': token,
                    'dst': dst, 'uri_path': uri_path
                })
    
    print(f"\nNON DELETE requests to coap.me: {len(coap_me_requests)}")
    for r in coap_me_requests:
        print(f"  Frame {r['frame']}: MID={r['mid']}, token={r['token']}, path={r['uri_path']}")
    
    mids_list = [r['mid'] for r in coap_me_requests]
    print(f"MIDs: {mids_list}")
    
    # Step 2: Find responses for these requests (match by token for NON)
    # Responses from coap.me (134.102.218.18) 
    successful_count = 0
    desired_outcome_count = 0
    
    for req in coap_me_requests:
        token = req['token']
        mid = req['mid']
        # For NON messages, responses match by token
        # Response from coap.me with matching token
        resp_raw = run_tshark_raw(FILE_A, 
            f"coap && ip.src==134.102.218.18 && coap.token=={token}",
            ["frame.number", "coap.mid", "coap.code", "coap.type"])
        
        if not resp_raw:
            # Try matching by MID
            resp_raw = run_tshark_raw(FILE_A,
                f"coap && ip.src==134.102.218.18 && coap.mid=={mid}",
                ["frame.number", "coap.mid", "coap.code", "coap.type"])
        
        print(f"\n  Responses for MID={mid}, token={token}:")
        print(f"    {resp_raw}")
        
        if resp_raw:
            for rl in resp_raw.split('\n'):
                rparts = rl.split('|')
                if len(rparts) >= 3:
                    resp_code = rparts[2].strip()
                    # Successful = 2.xx
                    if resp_code.startswith('2.'):
                        successful_count += 1
                        # Desired outcome for DELETE = 2.02
                        if resp_code == '2.02':
                            desired_outcome_count += 1
                        break
    
    print(f"\nCQ1a) NON DELETE to coap.me with successful response: {successful_count}")
    print(f"  MIDs: {mids_list}")
    print(f"\nCQ1b) Actually obtained desired outcome (2.02 Deleted): {desired_outcome_count}")

###############################################################################
# CQ2
###############################################################################
def solve_cq2():
    print("\n" + "=" * 70)
    print("CQ2: Resources with equal unique unsuccessful CON POST and PUT")
    print("=" * 70)
    
    # Find all CON POST (type=0, code=2) and CON PUT (type=0, code=3) to local server
    # Then match with responses to determine if unsuccessful
    
    # First: get all CON POST requests
    for method, code_num in [("POST", "2"), ("PUT", "3")]:
        raw = run_tshark_raw(FILE_A, f"coap.type==0 && coap.code=={code_num}",
            ["frame.number", "coap.mid", "coap.token", "ip.dst", "ip.src",
             "coap.opt.uri_path_recon", "coap.opt.uri_host"])
        print(f"\nAll CON {method} requests:")
        lines = raw.split('\n') if raw else []
        print(f"  Count: {len(lines)}")
        for l in lines[:5]:
            print(f"  {l}")
        if len(lines) > 5:
            print(f"  ... and {len(lines)-5} more")
    
    # Now systematically: get CON POST/PUT to local server with their responses
    # Local server = private IP (not 134.102.218.18, not public IPs)
    
    # Get all CON requests and their ACK responses
    # Use -2 pass analysis for request-response matching
    
    post_unsuccessful = collections.defaultdict(set)  # uri -> set of MIDs
    put_unsuccessful = collections.defaultdict(set)
    
    for method, code_num in [("POST", "2"), ("PUT", "3")]:
        raw = run_tshark_raw(FILE_A, f"coap.type==0 && coap.code=={code_num}",
            ["frame.number", "coap.mid", "ip.dst", "coap.opt.uri_path_recon"])
        
        if not raw:
            continue
            
        for line in raw.split('\n'):
            parts = line.split('|')
            if len(parts) < 4:
                continue
            frame, mid, dst, uri = parts[0].strip(), parts[1].strip(), parts[2].strip(), parts[3].strip()
            
            # Check if local server
            if dst.startswith('10.') or dst.startswith('192.168.') or dst.startswith('172.') or dst.startswith('127.') or dst.startswith('fd') or dst.startswith('fe80') or dst == '::1':
                # Find ACK response with same MID
                resp_raw = run_tshark_raw(FILE_A,
                    f"coap.type==2 && coap.mid=={mid} && ip.src=={dst}",
                    ["coap.code"])
                
                if resp_raw:
                    resp_code = resp_raw.split('\n')[0].strip()
                    # Unsuccessful = 4.xx or 5.xx
                    if resp_code.startswith('4.') or resp_code.startswith('5.'):
                        if method == "POST":
                            post_unsuccessful[uri].add(mid)
                        else:
                            put_unsuccessful[uri].add(mid)
    
    print(f"\nResources with unsuccessful CON POST:")
    for res, mids in sorted(post_unsuccessful.items()):
        print(f"  {res}: {len(mids)} unique (MIDs: {sorted(mids)})")
    
    print(f"\nResources with unsuccessful CON PUT:")
    for res, mids in sorted(put_unsuccessful.items()):
        print(f"  {res}: {len(mids)} unique (MIDs: {sorted(mids)})")
    
    # Find X=Y with X>0
    all_resources = set(list(post_unsuccessful.keys()) + list(put_unsuccessful.keys()))
    matching = []
    for res in sorted(all_resources):
        x = len(post_unsuccessful.get(res, set()))
        y = len(put_unsuccessful.get(res, set()))
        print(f"  {res}: POST={x}, PUT={y} {'*** MATCH ***' if x==y and x>0 else ''}")
        if x == y and x > 0:
            matching.append(res)
    
    print(f"\nCQ2) Answer: {len(matching)}")

###############################################################################
# CQ3
###############################################################################
def solve_cq3():
    print("\n" + "=" * 70)
    print("CQ3: Observe notifications for /dining_room/temperature")
    print("=" * 70)
    
    # Step 1: Find observe registrations for /dining_room/temperature
    raw = run_tshark_raw(FILE_A,
        'coap.opt.observe==0 && coap.opt.uri_path_recon contains "dining_room/temperature"',
        ["frame.number", "coap.mid", "coap.token", "ip.src", "ip.dst"])
    
    print(f"Observe registrations:\n{raw}")
    
    tokens = set()
    if raw:
        for line in raw.split('\n'):
            parts = line.split('|')
            if len(parts) >= 3:
                tokens.add(parts[2].strip())
    
    print(f"Tokens: {tokens}")
    
    if not tokens:
        # Try without recon
        raw = run_tshark_raw(FILE_A,
            'coap.opt.observe==0 && coap.opt.uri_path contains "dining_room"',
            ["frame.number", "coap.mid", "coap.token", "ip.src", "ip.dst", "coap.opt.uri_path_recon"])
        print(f"Alternate search:\n{raw}")
        if raw:
            for line in raw.split('\n'):
                parts = line.split('|')
                if len(parts) >= 3:
                    tokens.add(parts[2].strip())
    
    # Step 2: Find notifications (responses with observe option) for these tokens
    # Notifications are responses (2.05) with observe option
    for token in tokens:
        print(f"\nNotifications for token {token}:")
        raw = run_tshark_raw(FILE_A,
            f'coap.opt.observe && coap.code==\"2.05\" && coap.token=={token}',
            ["frame.number", "coap.mid", "coap.type", "coap.opt.observe", "coap.payload", "data.data"])
        
        if not raw:
            raw = run_tshark_raw(FILE_A,
                f'coap.opt.observe && coap.token=={token} && !(coap.code==1)',
                ["frame.number", "coap.mid", "coap.type", "coap.code", "coap.opt.observe", "coap.payload"])
        
        print(raw[:3000])
        
        if raw:
            lines = raw.split('\n')
            # Remove retransmissions (same MID)
            seen_mids = set()
            unique = []
            payloads = []
            for line in lines:
                parts = line.split('|')
                mid = parts[1].strip() if len(parts) > 1 else ''
                if mid and mid not in seen_mids:
                    seen_mids.add(mid)
                    unique.append(parts)
                    payload = parts[4].strip() if len(parts) > 4 else parts[-1].strip()
                    payloads.append(payload)
            
            print(f"\nCQ3a) Unique notifications (no retransmissions): {len(unique)}")
            
            # Useless = same payload as previous
            useless = 0
            for i in range(1, len(payloads)):
                if payloads[i] == payloads[i-1] and payloads[i]:
                    useless += 1
                    print(f"  Useless: index {i}, payload={payloads[i]}")
            
            print(f"\nCQ3b) Useless notifications: {useless}")

###############################################################################
# CQ4
###############################################################################
def solve_cq4():
    print("\n" + "=" * 70)
    print("CQ4: MQTT-SN messages received by clients from local broker (port 1885)")
    print("=" * 70)
    
    # Messages FROM broker (src port 1885) TO clients
    count = run_tshark_count(FILE_A, "mqttsn && udp.srcport==1885")
    print(f"MQTT-SN messages from local broker (srcport 1885): {count}")
    
    # Also show message type breakdown
    raw = run_tshark_raw(FILE_A, "mqttsn && udp.srcport==1885",
        ["frame.number", "mqttsn.msg_type"])
    
    if raw:
        types = collections.Counter()
        for line in raw.split('\n'):
            parts = line.split('|')
            if len(parts) >= 2:
                types[parts[1].strip()] += 1
        print(f"Message types: {dict(types)}")
    
    # Also try without malformed
    count2 = run_tshark_count(FILE_A, "mqttsn && udp.srcport==1885 && !_ws.malformed")
    print(f"Without malformed: {count2}")
    
    print(f"\nCQ4) Answer: {count2}")

###############################################################################
# Main
###############################################################################
if __name__ == '__main__':
    # Fix FILE_B path
    global FILE_B_FIXED
    FILE_B = "/Users/anasuyasatapathy/Desktop/iotchallenge---2/B.pcapng"
    
    solve_cq1()
    solve_cq2()
    solve_cq3()
    solve_cq4()
