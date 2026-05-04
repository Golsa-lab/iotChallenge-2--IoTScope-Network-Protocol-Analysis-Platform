#!/usr/bin/env python3
"""Parse MQTT-SN messages on port 1885 from A.pcapng using scapy."""
import subprocess, struct, collections

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
FILE_A = "/Users/anasuyasatapathy/Desktop/iotchallenge---2/A.pcapng"

# MQTT-SN message types
MQTTSN_TYPES = {
    0x00: "ADVERTISE", 0x01: "SEARCHGW", 0x02: "GWINFO",
    0x04: "CONNECT", 0x05: "CONNACK", 0x06: "WILLTOPICREQ",
    0x07: "WILLTOPIC", 0x08: "WILLMSGREQ", 0x09: "WILLMSG",
    0x0A: "REGISTER", 0x0B: "REGACK", 0x0C: "PUBLISH",
    0x0D: "PUBACK", 0x0E: "PUBCOMP", 0x0F: "PUBREC",
    0x10: "PUBREL", 0x12: "SUBSCRIBE", 0x13: "SUBACK",
    0x14: "UNSUBSCRIBE", 0x15: "UNSUBACK", 0x16: "PINGREQ",
    0x17: "PINGRESP", 0x18: "DISCONNECT", 0x1A: "WILLTOPICUPD",
    0x1B: "WILLTOPICRESP", 0x1C: "WILLMSGUPD", 0x1D: "WILLMSGRESP",
}

# Get all UDP packets on port 1885 with raw hex data
# Source port 1885 = messages FROM broker TO clients
result = subprocess.run([
    TSHARK, "-r", FILE_A, "-Y", "udp.srcport==1885",
    "-T", "fields", "-e", "frame.number", "-e", "data.data",
    "-E", "separator=|"
], capture_output=True, text=True)

count = 0
msg_types = collections.Counter()
malformed = 0

for line in result.stdout.strip().split('\n'):
    if not line.strip():
        continue
    parts = line.split('|')
    frame = parts[0]
    hex_data = parts[1] if len(parts) > 1 else ''
    
    if not hex_data:
        continue
    
    # Remove colons/spaces
    hex_data = hex_data.replace(':', '').replace(' ', '')
    try:
        data = bytes.fromhex(hex_data)
    except:
        malformed += 1
        continue
    
    if len(data) < 2:
        malformed += 1
        continue
    
    # Parse MQTT-SN length and type
    if data[0] == 0x01:
        # 3-byte length header
        if len(data) < 4:
            malformed += 1
            continue
        length = struct.unpack('>H', data[1:3])[0]
        msg_type = data[3]
    else:
        length = data[0]
        msg_type = data[1]
    
    type_name = MQTTSN_TYPES.get(msg_type, f"UNKNOWN(0x{msg_type:02x})")
    msg_types[type_name] += 1
    count += 1

print(f"MQTT-SN messages FROM local broker (srcport 1885): {count}")
print(f"Malformed/skipped: {malformed}")
print(f"\nMessage type breakdown:")
for t, c in sorted(msg_types.items()):
    print(f"  {t}: {c}")

print(f"\nCQ4) Answer: {count}")

# Also count messages TO broker (dstport 1885) for reference
result2 = subprocess.run([
    TSHARK, "-r", FILE_A, "-Y", "udp.dstport==1885",
    "-T", "fields", "-e", "frame.number", "-e", "data.data",
    "-E", "separator=|"
], capture_output=True, text=True)

count2 = 0
for line in result2.stdout.strip().split('\n'):
    if line.strip():
        count2 += 1

print(f"\nFor reference - MQTT-SN messages TO broker (dstport 1885): {count2}")
