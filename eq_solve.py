#!/usr/bin/env python3
"""
Part 2 - Exercise: Energy Computation
EQ1: Total communication energy over 1 hour for CoAP and MQTT
EQ2: Protocol choice when actuator wakes every 30 minutes
"""

# Parameters
E_TX = 50  # nJ/bit
E_RX = 58  # nJ/bit
PAYLOAD = 12  # bytes
TOPIC_RESOURCE = 8  # bytes

# Message sizes (already include header + payload)
COAP_CON_PUT = 70  # bytes
COAP_PUT_ACK = 15  # bytes
MQTT_SUBSCRIBE = 65  # bytes
MQTT_SUB_ACK = 55  # bytes
MQTT_PUBLISH = 75  # bytes
MQTT_PUB_ACK = 50  # bytes
MQTT_CONNECT = 60  # bytes  (also DISCONNECT)
MQTT_CONNECT_ACK = 50  # bytes

# Sensor transmits every 2 minutes → 30 measurements per hour
# Devices start disconnected
# MQTT connections closed gracefully with non-acknowledged DISCONNECT
# QoS 1 for MQTT
# Ideal communication (no losses)

measurements_per_hour = 60 // 2  # = 30

print("=" * 70)
print("EQ1a: CoAP (direct communication)")
print("=" * 70)

# CoAP: Sensor sends CON PUT to actuator, actuator responds with ACK
# Per measurement cycle:
#   Sensor: TX CON PUT (70B) + RX PUT ACK (15B)
#   Actuator: RX CON PUT (70B) + TX PUT ACK (15B)

sensor_coap_per_msg = E_TX * 70 * 8 + E_RX * 15 * 8  # nJ
actuator_coap_per_msg = E_RX * 70 * 8 + E_TX * 15 * 8  # nJ

total_coap_sensor = sensor_coap_per_msg * measurements_per_hour
total_coap_actuator = actuator_coap_per_msg * measurements_per_hour
total_coap = total_coap_sensor + total_coap_actuator

print(f"Per measurement:")
print(f"  Sensor: TX {70}B + RX {15}B")
print(f"    Energy = {E_TX}*{70}*8 + {E_RX}*{15}*8 = {sensor_coap_per_msg} nJ")
print(f"  Actuator: RX {70}B + TX {15}B")
print(f"    Energy = {E_RX}*{70}*8 + {E_TX}*{15}*8 = {actuator_coap_per_msg} nJ")
print(f"\nTotal per cycle: {sensor_coap_per_msg + actuator_coap_per_msg} nJ")
print(f"Over 1 hour ({measurements_per_hour} measurements):")
print(f"  Sensor total: {total_coap_sensor} nJ = {total_coap_sensor/1000} µJ")
print(f"  Actuator total: {total_coap_actuator} nJ = {total_coap_actuator/1000} µJ")
print(f"  TOTAL: {total_coap} nJ = {total_coap/1000} µJ")

print("\n" + "=" * 70)
print("EQ1b: MQTT (via gateway)")
print("=" * 70)

# MQTT via gateway:
# Sensor publishes to gateway, gateway forwards to actuator
# 
# Both sensor and actuator need to CONNECT/DISCONNECT for each wake cycle
# Sensor wakes every 2 minutes to publish
# Actuator wakes every 2 minutes to receive (in normal EQ1 scenario)
#
# Sensor per wake cycle:
#   TX CONNECT (60B) + RX CONNACK (50B)
#   TX PUBLISH (75B) + RX PUBACK (50B)  [QoS 1]
#   TX DISCONNECT (60B) [non-acknowledged]
#
# Actuator per wake cycle:
#   TX CONNECT (60B) + RX CONNACK (50B)
#   TX SUBSCRIBE (65B) + RX SUBACK (55B)
#   RX PUBLISH (75B) + TX PUBACK (50B)  [QoS 1]
#   TX DISCONNECT (60B) [non-acknowledged]

# SENSOR per wake cycle:
sensor_mqtt_tx_per_cycle = (MQTT_CONNECT + MQTT_PUBLISH + MQTT_CONNECT) * 8  # bits (CONNECT + PUBLISH + DISCONNECT, DISCONNECT = same size as CONNECT)
sensor_mqtt_rx_per_cycle = (MQTT_CONNECT_ACK + MQTT_PUB_ACK) * 8  # bits (CONNACK + PUBACK)

sensor_mqtt_energy_per_cycle = E_TX * sensor_mqtt_tx_per_cycle + E_RX * sensor_mqtt_rx_per_cycle

print(f"\nSensor per wake cycle:")
print(f"  TX: CONNECT({MQTT_CONNECT}B) + PUBLISH({MQTT_PUBLISH}B) + DISCONNECT({MQTT_CONNECT}B) = {MQTT_CONNECT + MQTT_PUBLISH + MQTT_CONNECT}B")
print(f"  RX: CONNACK({MQTT_CONNECT_ACK}B) + PUBACK({MQTT_PUB_ACK}B) = {MQTT_CONNECT_ACK + MQTT_PUB_ACK}B")
print(f"  Energy = {E_TX}*{MQTT_CONNECT + MQTT_PUBLISH + MQTT_CONNECT}*8 + {E_RX}*{MQTT_CONNECT_ACK + MQTT_PUB_ACK}*8 = {sensor_mqtt_energy_per_cycle} nJ")

# ACTUATOR per wake cycle:
actuator_mqtt_tx_per_cycle = (MQTT_CONNECT + MQTT_SUBSCRIBE + MQTT_PUB_ACK + MQTT_CONNECT) * 8  # CONNECT + SUBSCRIBE + PUBACK + DISCONNECT
actuator_mqtt_rx_per_cycle = (MQTT_CONNECT_ACK + MQTT_SUB_ACK + MQTT_PUBLISH) * 8  # CONNACK + SUBACK + PUBLISH

actuator_mqtt_energy_per_cycle = E_TX * actuator_mqtt_tx_per_cycle + E_RX * actuator_mqtt_rx_per_cycle

print(f"\nActuator per wake cycle:")
print(f"  TX: CONNECT({MQTT_CONNECT}B) + SUBSCRIBE({MQTT_SUBSCRIBE}B) + PUBACK({MQTT_PUB_ACK}B) + DISCONNECT({MQTT_CONNECT}B) = {MQTT_CONNECT + MQTT_SUBSCRIBE + MQTT_PUB_ACK + MQTT_CONNECT}B")
print(f"  RX: CONNACK({MQTT_CONNECT_ACK}B) + SUBACK({MQTT_SUB_ACK}B) + PUBLISH({MQTT_PUBLISH}B) = {MQTT_CONNECT_ACK + MQTT_SUB_ACK + MQTT_PUBLISH}B")
print(f"  Energy = {E_TX}*{MQTT_CONNECT + MQTT_SUBSCRIBE + MQTT_PUB_ACK + MQTT_CONNECT}*8 + {E_RX}*{MQTT_CONNECT_ACK + MQTT_SUB_ACK + MQTT_PUBLISH}*8 = {actuator_mqtt_energy_per_cycle} nJ")

total_sensor_mqtt = sensor_mqtt_energy_per_cycle * measurements_per_hour
total_actuator_mqtt = actuator_mqtt_energy_per_cycle * measurements_per_hour
total_mqtt = total_sensor_mqtt + total_actuator_mqtt

print(f"\nOver 1 hour ({measurements_per_hour} cycles):")
print(f"  Sensor total: {total_sensor_mqtt} nJ = {total_sensor_mqtt/1000} µJ")
print(f"  Actuator total: {total_actuator_mqtt} nJ = {total_actuator_mqtt/1000} µJ")
print(f"  TOTAL: {total_mqtt} nJ = {total_mqtt/1000} µJ")

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"EQ1a) CoAP total energy: {total_coap/1000} µJ")
print(f"EQ1b) MQTT total energy: {total_mqtt/1000} µJ")
print(f"\nCoAP is {'more' if total_coap > total_mqtt else 'less'} energy-intensive than MQTT")

print("\n" + "=" * 70)
print("EQ2: Actuator wakes every 30 minutes")
print("=" * 70)
print("""
If actuator wakes only every 30 min, it misses 14 out of 15 sensor readings
per 30-min window (sensor sends every 2 min = 15 per 30 min).

With MQTT + retain flag + clean_session=0:
- Sensor publishes with retain=1 to gateway
- Actuator connects every 30 min with clean_session=0
- Broker stores the latest retained message
- When actuator reconnects, it gets the latest value immediately
- Only 1 PUBLISH received instead of 15

With CoAP observe:
- Sensor uses CON PUT to actuator
- If actuator is sleeping, CON messages are retransmitted up to MAX_TRANSMISSIONS=3
  with RTO=30s, then dropped
- Most sensor readings are LOST (actuator sleeps for 30 min, retransmissions exhaust 
  in ~90s)
- Massive energy waste on failed retransmissions

MQTT with retain is superior: sensor publishes normally, actuator wakes
infrequently and gets latest value. CoAP wastes energy on retransmissions 
to sleeping actuator.
""")

# EQ2 energy calculation
print("MQTT with retain (actuator wakes every 30 min):")
# Sensor: same as before, wakes 30 times
# Actuator: wakes only 2 times per hour
actuator_wakes = 60 // 30  # = 2
sensor_cycles = 30

# With retain + clean_session=0, actuator only needs CONNECT + SUBACK once (persistent session)
# Actually with clean_session=0, subscriptions persist. On reconnect:
# TX CONNECT + RX CONNACK + RX PUBLISH (latest retained) + TX PUBACK + TX DISCONNECT
actuator_mqtt_30min_tx = (MQTT_CONNECT + MQTT_PUB_ACK + MQTT_CONNECT) * 8
actuator_mqtt_30min_rx = (MQTT_CONNECT_ACK + MQTT_PUBLISH) * 8
# First connect also needs SUBSCRIBE
actuator_mqtt_first_tx = (MQTT_CONNECT + MQTT_SUBSCRIBE + MQTT_PUB_ACK + MQTT_CONNECT) * 8
actuator_mqtt_first_rx = (MQTT_CONNECT_ACK + MQTT_SUB_ACK + MQTT_PUBLISH) * 8

# Energy
# First wake: full connect + subscribe
e_first = E_TX * actuator_mqtt_first_tx + E_RX * actuator_mqtt_first_rx
# Subsequent: just connect (subscription persists with clean_session=0)
e_subsequent = E_TX * actuator_mqtt_30min_tx + E_RX * actuator_mqtt_30min_rx

total_actuator_eq2 = e_first + (actuator_wakes - 1) * e_subsequent
total_sensor_eq2 = sensor_mqtt_energy_per_cycle * sensor_cycles
total_eq2_mqtt = total_sensor_eq2 + total_actuator_eq2

print(f"  Actuator energy: {total_actuator_eq2} nJ = {total_actuator_eq2/1000} µJ")
print(f"  Sensor energy: {total_sensor_eq2} nJ = {total_sensor_eq2/1000} µJ")
print(f"  TOTAL: {total_eq2_mqtt} nJ = {total_eq2_mqtt/1000} µJ")

print("\nCoAP with retransmissions (actuator wakes every 30 min):")
# Sensor: sends CON PUT every 2 min, actuator sleeping
# For messages when actuator is asleep: retransmit up to MAX_TRANSMISSIONS=3
# Each of the 14 missed messages: 3 TX attempts + no ACK
# 1 message hits the wake window: normal exchange
# Per 30-min window: 15 messages total, 14 fail, 1 succeeds

failed_per_window = 14  # sensor readings when actuator sleeps
success_per_window = 1

# Failed: sensor TXs CON PUT 3 times each, no ACK received
sensor_failed_energy = failed_per_window * 3 * E_TX * COAP_CON_PUT * 8
# Successful: normal exchange
sensor_success_energy = success_per_window * (E_TX * COAP_CON_PUT * 8 + E_RX * COAP_PUT_ACK * 8)
# Actuator success:
actuator_success_energy = success_per_window * (E_RX * COAP_CON_PUT * 8 + E_TX * COAP_PUT_ACK * 8)

windows_per_hour = 2
total_sensor_coap_eq2 = (sensor_failed_energy + sensor_success_energy) * windows_per_hour
total_actuator_coap_eq2 = actuator_success_energy * windows_per_hour
total_eq2_coap = total_sensor_coap_eq2 + total_actuator_coap_eq2

print(f"  Sensor energy: {total_sensor_coap_eq2} nJ = {total_sensor_coap_eq2/1000} µJ")
print(f"  Actuator energy: {total_actuator_coap_eq2} nJ = {total_actuator_coap_eq2/1000} µJ")
print(f"  TOTAL: {total_eq2_coap} nJ = {total_eq2_coap/1000} µJ")
