#!/usr/bin/env python3
"""
Analysis script for A.pcapng - CQ1 through CQ4
IoT Challenge #2 - Anasuya Satapathy (11175090)
"""

import pyshark
import collections

PCAP_FILE = "A.pcapng"

###############################################################################
# CQ1a) Find all NON Confirmable DELETE requests directed to coap.me server
#        that received a successful response. Take note of the MID.
# CQ1b) How many actually obtained the desired outcome?
###############################################################################

def solve_cq1():
    print("=" * 60)
    print("CQ1: NON Confirmable DELETE requests to coap.me")
    print("=" * 60)

    # First, find the IP of coap.me by looking at DNS or known IP (134.102.218.18)
    # coap.me typically resolves to 134.102.218.18
    # We'll look for NON DELETE requests to coap.me server

    # Load capture with CoAP filter
    cap = pyshark.FileCapture(PCAP_FILE, display_filter='coap')

    # Collect all NON DELETE requests
    non_delete_requests = []  # list of (mid, dst_ip, frame_number)
    responses = {}  # mid -> list of response codes

    for pkt in cap:
        try:
            coap = pkt.coap
            # Check type: NON = 1
            msg_type = int(coap.type)
            code = coap.code
            mid = int(coap.mid)

            # NON type = 1, DELETE code = 4 (0.04 -> code field "4" or "0.04")
            # In pyshark, code might be displayed differently
            # DELETE = method code 4, displayed as "4" or "0.04"
            # Check if it's a request (code class 0) with method DELETE (code 4)
            
            code_str = str(coap.code)
            
            # Identify if this is a NON DELETE request
            if msg_type == 1:  # NON
                # Check if DELETE request
                if hasattr(coap, 'code') and ('DELETE' in str(getattr(coap, '_all_fields', {}).get('coap.code', '')) or code_str == '4' or code_str == '0.04'):
                    # Try to find destination - need to check if directed to coap.me
                    dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else (pkt.ipv6.dst if hasattr(pkt, 'ipv6') else None)
                    src_ip = pkt.ip.src if hasattr(pkt, 'ip') else (pkt.ipv6.src if hasattr(pkt, 'ipv6') else None)
                    non_delete_requests.append({
                        'mid': mid,
                        'dst_ip': dst_ip,
                        'src_ip': src_ip,
                        'frame': pkt.number,
                        'code': code_str
                    })
        except Exception as e:
            pass

    cap.close()

    print(f"\nAll NON type packets found, now filtering DELETE requests to coap.me...")
    
    # Let's be more thorough - use display filter
    cap2 = pyshark.FileCapture(PCAP_FILE, display_filter='coap.type==1 && coap.code==4')
    
    non_delete_to_coap_me = []
    all_non_delete = []
    
    for pkt in cap2:
        try:
            coap = pkt.coap
            mid = int(coap.mid)
            dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else "?"
            src_ip = pkt.ip.src if hasattr(pkt, 'ip') else "?"
            uri_host = getattr(coap, 'opt_uri_host', None)
            uri_path = getattr(coap, 'opt_uri_path_recon', getattr(coap, 'opt_uri_path', ''))
            
            all_non_delete.append({
                'mid': mid,
                'dst_ip': dst_ip,
                'src_ip': src_ip,
                'frame': pkt.number,
                'uri_host': uri_host,
                'uri_path': uri_path
            })
            
            # Check if directed to coap.me
            # coap.me IP: 134.102.218.18 or check uri_host
            is_coap_me = False
            if uri_host and 'coap.me' in str(uri_host):
                is_coap_me = True
            if dst_ip == '134.102.218.18':
                is_coap_me = True
            
            if is_coap_me:
                non_delete_to_coap_me.append({
                    'mid': mid,
                    'dst_ip': dst_ip,
                    'src_ip': src_ip,
                    'frame': pkt.number,
                    'uri_host': uri_host,
                    'uri_path': uri_path
                })
                
        except Exception as e:
            pass
    
    cap2.close()
    
    print(f"\nTotal NON DELETE requests: {len(all_non_delete)}")
    for r in all_non_delete:
        print(f"  Frame {r['frame']}: MID={r['mid']}, dst={r['dst_ip']}, host={r['uri_host']}, path={r['uri_path']}")
    
    print(f"\nNON DELETE requests to coap.me: {len(non_delete_to_coap_me)}")
    for r in non_delete_to_coap_me:
        print(f"  Frame {r['frame']}: MID={r['mid']}, dst={r['dst_ip']}, path={r['uri_path']}")
    
    # Now find successful responses for these MIDs
    # For NON requests, responses are matched by token (not MID necessarily)
    # But let's also check MID-based matching
    
    mids = [r['mid'] for r in non_delete_to_coap_me]
    print(f"\nMIDs of NON DELETE to coap.me: {mids}")
    
    # Check responses from coap.me
    if non_delete_to_coap_me:
        coap_me_ip = non_delete_to_coap_me[0]['dst_ip']
        cap3 = pyshark.FileCapture(PCAP_FILE, display_filter=f'coap && ip.src=={coap_me_ip}')
        
        responses_from_coap_me = []
        for pkt in cap3:
            try:
                coap = pkt.coap
                mid = int(coap.mid)
                code = str(coap.code)
                token = getattr(coap, 'token', '')
                responses_from_coap_me.append({
                    'mid': mid,
                    'code': code,
                    'frame': pkt.number,
                    'token': token
                })
            except:
                pass
        cap3.close()
        
        # Match responses to our DELETE requests
        successful_mids = []
        desired_outcome_mids = []
        
        for req in non_delete_to_coap_me:
            mid = req['mid']
            # Find response with same MID (for NON, response is also NON with same token)
            matching = [r for r in responses_from_coap_me if r['mid'] == mid]
            if matching:
                for m in matching:
                    print(f"  Response for MID {mid}: code={m['code']}, frame={m['frame']}")
                    # Successful response: 2.xx codes
                    code_val = m['code']
                    if code_val.startswith('2.') or (code_val.startswith('2') and '.' in code_val):
                        successful_mids.append(mid)
                        # DELETE desired outcome = 2.02 Deleted
                        if '2.02' in code_val:
                            desired_outcome_mids.append(mid)
            else:
                print(f"  No response found for MID {mid}")
        
        print(f"\nCQ1a) NON DELETE requests to coap.me with successful response: {len(successful_mids)}")
        print(f"  MIDs: {successful_mids}")
        print(f"\nCQ1b) Requests that actually obtained desired outcome (2.02 Deleted): {len(desired_outcome_mids)}")
        print(f"  MIDs: {desired_outcome_mids}")

###############################################################################
# CQ2) How many CoAP resources in the local server received the same
#      number of unique unsuccessful Confirmable POST and PUT requests?
###############################################################################

def solve_cq2():
    print("\n" + "=" * 60)
    print("CQ2: CoAP resources with equal unsuccessful CON POST and PUT")
    print("=" * 60)
    
    # Local server = localhost / 127.0.0.1 or local IP
    # First find local server IP
    # CON = type 0, POST = code 2, PUT = code 3
    
    # Find unsuccessful CON POST requests to local server
    # Unsuccessful = response with non-2.xx code
    
    # Step 1: Find all CON POST and CON PUT to local server
    # Local server likely on 127.0.0.1 or a private IP
    
    # Let's first discover what IPs are used
    cap = pyshark.FileCapture(PCAP_FILE, display_filter='coap.type==0 && (coap.code==2 || coap.code==3)')
    
    requests = []  # (mid, token, code, dst_ip, src_ip, uri_path, frame)
    
    for pkt in cap:
        try:
            coap = pkt.coap
            mid = int(coap.mid)
            code = str(coap.code)
            token = getattr(coap, 'token', '')
            dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else ''
            src_ip = pkt.ip.src if hasattr(pkt, 'ip') else ''
            uri_path = getattr(coap, 'opt_uri_path_recon', getattr(coap, 'opt_uri_path', ''))
            
            requests.append({
                'mid': mid,
                'code': code,  # 2=POST, 3=PUT
                'token': token,
                'dst_ip': dst_ip,
                'src_ip': src_ip,
                'uri_path': str(uri_path),
                'frame': pkt.number
            })
        except:
            pass
    cap.close()
    
    print(f"Total CON POST/PUT requests: {len(requests)}")
    
    # Identify local server IPs (private IPs, not coap.me)
    dst_ips = set(r['dst_ip'] for r in requests)
    print(f"Destination IPs: {dst_ips}")
    
    # Filter to local server (private IPs: 10.x, 172.16-31.x, 192.168.x, 127.x)
    def is_local(ip):
        return (ip.startswith('10.') or ip.startswith('192.168.') or 
                ip.startswith('172.') or ip.startswith('127.') or
                ip.startswith('fd') or ip.startswith('fe80'))
    
    local_requests = [r for r in requests if is_local(r['dst_ip'])]
    print(f"CON POST/PUT to local server: {len(local_requests)}")
    
    # Now find responses for these requests
    # Load all CoAP responses
    cap2 = pyshark.FileCapture(PCAP_FILE, display_filter='coap')
    
    all_responses = []
    for pkt in cap2:
        try:
            coap = pkt.coap
            msg_type = int(coap.type)
            code = str(coap.code)
            mid = int(coap.mid)
            token = getattr(coap, 'token', '')
            src_ip = pkt.ip.dst if hasattr(pkt, 'ip') else ''  # Note: reversed for response matching
            
            # Response codes start with non-zero class (e.g., 2.xx, 4.xx, 5.xx)
            # ACK type = 2
            if '.' in code:
                code_class = int(code.split('.')[0])
                if code_class >= 2:  # It's a response
                    all_responses.append({
                        'mid': mid,
                        'code': code,
                        'token': token,
                        'frame': pkt.number,
                        'msg_type': msg_type,
                        'src_ip': pkt.ip.src if hasattr(pkt, 'ip') else ''
                    })
        except:
            pass
    cap2.close()
    
    print(f"Total CoAP responses: {len(all_responses)}")
    
    # Match requests to responses and find unsuccessful ones
    # For CON requests, response is ACK with same MID
    post_unsuccessful = collections.defaultdict(set)  # resource -> set of unique MIDs
    put_unsuccessful = collections.defaultdict(set)
    
    for req in local_requests:
        mid = req['mid']
        # Find ACK response with same MID
        matching_responses = [r for r in all_responses if r['mid'] == mid]
        
        for resp in matching_responses:
            code = resp['code']
            code_class = int(code.split('.')[0]) if '.' in code else -1
            # Unsuccessful = not 2.xx (i.e., 4.xx or 5.xx)
            if code_class >= 4:  # Client error or server error
                resource = req['uri_path']
                if req['code'] == '2':  # POST
                    post_unsuccessful[resource].add(mid)
                elif req['code'] == '3':  # PUT
                    put_unsuccessful[resource].add(mid)
    
    print(f"\nResources with unsuccessful CON POST:")
    for res, mids in sorted(post_unsuccessful.items()):
        print(f"  {res}: {len(mids)} unique requests (MIDs: {mids})")
    
    print(f"\nResources with unsuccessful CON PUT:")
    for res, mids in sorted(put_unsuccessful.items()):
        print(f"  {res}: {len(mids)} unique requests (MIDs: {mids})")
    
    # Find resources where X=Y and X>0
    all_resources = set(list(post_unsuccessful.keys()) + list(put_unsuccessful.keys()))
    matching_resources = []
    
    for res in all_resources:
        x = len(post_unsuccessful.get(res, set()))
        y = len(put_unsuccessful.get(res, set()))
        if x == y and x > 0:
            matching_resources.append(res)
            print(f"\n  MATCH: {res} -> POST={x}, PUT={y}")
    
    print(f"\nCQ2) Number of resources with X=Y (X>0): {len(matching_resources)}")

###############################################################################
# CQ3a) Observe notifications for /dining_room/temperature (ignoring retrans)
# CQ3b) How many are useless?
###############################################################################

def solve_cq3():
    print("\n" + "=" * 60)
    print("CQ3: Observe notifications for /dining_room/temperature")
    print("=" * 60)
    
    # Observe notifications have the Observe option set
    # Filter: coap with observe option and uri contains dining_room/temperature
    # Or responses with observe option from the server
    
    cap = pyshark.FileCapture(PCAP_FILE, display_filter='coap.opt.observe')
    
    notifications = []
    registrations = []
    
    for pkt in cap:
        try:
            coap = pkt.coap
            msg_type = int(coap.type)
            code = str(coap.code)
            mid = int(coap.mid)
            observe = getattr(coap, 'opt_observe', None)
            token = getattr(coap, 'token', '')
            uri_path = getattr(coap, 'opt_uri_path_recon', getattr(coap, 'opt_uri_path', ''))
            payload = getattr(coap, 'payload', '')
            
            # Registration: GET with Observe=0
            if str(observe) == '0' and 'dining_room' in str(uri_path) and 'temperature' in str(uri_path):
                registrations.append({
                    'mid': mid, 'token': token, 'frame': pkt.number,
                    'uri_path': str(uri_path), 'observe': observe
                })
            
            # Notification: response with Observe option (observe > 0 or any value in response)
            # Notifications are responses (2.05 Content) with Observe option
            if '.' in code:
                code_class = int(code.split('.')[0])
                if code_class == 2:  # Success response
                    # Check if this relates to dining_room/temperature
                    # We need to match by token to the registration
                    notifications.append({
                        'mid': mid, 'token': token, 'code': code,
                        'frame': pkt.number, 'observe': str(observe),
                        'msg_type': msg_type, 'payload': str(payload),
                        'uri_path': str(uri_path)
                    })
        except:
            pass
    cap.close()
    
    print(f"Observe registrations for dining_room/temperature: {len(registrations)}")
    for r in registrations:
        print(f"  Frame {r['frame']}: token={r['token']}, MID={r['mid']}")
    
    # Get tokens used for dining_room/temperature observe
    observe_tokens = set(r['token'] for r in registrations)
    print(f"Tokens for dining_room/temperature: {observe_tokens}")
    
    # Filter notifications by token
    dining_notifications = [n for n in notifications if n['token'] in observe_tokens]
    print(f"\nAll notifications with matching tokens: {len(dining_notifications)}")
    
    # Remove retransmissions (same MID = retransmission)
    seen_mids = set()
    unique_notifications = []
    for n in dining_notifications:
        if n['mid'] not in seen_mids:
            seen_mids.add(n['mid'])
            unique_notifications.append(n)
    
    print(f"Unique notifications (no retransmissions): {len(unique_notifications)}")
    for n in unique_notifications:
        print(f"  Frame {n['frame']}: MID={n['mid']}, observe={n['observe']}, code={n['code']}, payload={n['payload'][:50]}")
    
    print(f"\nCQ3a) Separate observe notifications: {len(unique_notifications)}")
    
    # CQ3b) Useless notifications = notifications with same value as previous
    # (no change in temperature = waste of traffic)
    useless_count = 0
    prev_payload = None
    for n in unique_notifications:
        if prev_payload is not None and n['payload'] == prev_payload:
            useless_count += 1
            print(f"  USELESS: Frame {n['frame']}, payload={n['payload'][:50]} (same as previous)")
        prev_payload = n['payload']
    
    print(f"\nCQ3b) Useless notifications: {useless_count}")

###############################################################################
# CQ4) MQTT-SN messages received by clients from local broker on port 1885
###############################################################################

def solve_cq4():
    print("\n" + "=" * 60)
    print("CQ4: MQTT-SN messages received by clients from local broker (port 1885)")
    print("=" * 60)
    
    # MQTT-SN on port 1885
    # Messages FROM broker TO clients = source port 1885
    cap = pyshark.FileCapture(PCAP_FILE, display_filter='mqttsn && udp.srcport==1885')
    
    count = 0
    msg_types = collections.Counter()
    
    for pkt in cap:
        try:
            count += 1
            # Try to get message type
            if hasattr(pkt, 'mqttsn'):
                msg_type = getattr(pkt.mqttsn, 'msg_type', 'unknown')
                msg_types[str(msg_type)] += 1
        except:
            pass
    cap.close()
    
    print(f"Total MQTT-SN messages from broker (port 1885) to clients: {count}")
    print(f"Message types: {dict(msg_types)}")
    print(f"\nCQ4) Answer: {count}")

###############################################################################
# Main
###############################################################################

if __name__ == '__main__':
    print("Analyzing A.pcapng...")
    print()
    solve_cq1()
    solve_cq2()
    solve_cq3()
    solve_cq4()
