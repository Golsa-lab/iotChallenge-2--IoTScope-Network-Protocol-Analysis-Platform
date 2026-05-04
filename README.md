# IoT Challenge 2 - Network Protocol Analysis

A comprehensive analysis and solution set for IoT Challenge 2, focusing on network packet analysis using CoAP, MQTT-SN, and other IoT protocols captured in PCAP files.

## 📋 Overview

This project provides solutions to various challenges related to IoT network protocol analysis. It includes packet capture analysis, protocol parsing, and data extraction from network traffic using tools like Wireshark and custom Python scripts.

## 🎯 Challenge Questions

The project addresses multiple challenge questions (CQ) spanning various IoT protocols and network analysis techniques:

- **CQ2**: Analysis of CoAP resources with equal unique unsuccessful CON POST and PUT requests
- **CQ3**: Data extraction and verification from CoAP protocol exchanges
- **CQ4**: MQTT-SN protocol message parsing and analysis on port 1885
- **CQ5**: Broker comparison and protocol analysis
- **CQ6b**: Advanced network protocol analysis
- **CQ8**: Data visualization and plotting

## 📁 Project Structure

```
├── A.pcapng                          # Network capture file A (primary analysis)
├── B.pcapng                          # Network capture file B (secondary analysis)
├── analyze_A.py                      # Main analysis script for capture file A
├── analyze_A_tshark.py               # Wireshark/tshark-based analysis for A
├── analyze_B.py                      # Analysis script for capture file B
├── cq2_solve.py                      # CQ2: CoAP POST/PUT analysis
├── cq3_extract.py                    # CQ3: Data extraction solution
├── cq4_mqttsn.py                     # CQ4: MQTT-SN protocol analysis
├── cq8_plot.py                       # CQ8: Data visualization
├── eq_solve.py                       # Additional equation solving utilities
├── verify_cq3.py                     # Verification script for CQ3
├── verify_cq5.py                     # Verification script for CQ5
├── verify_cq5_allbrokers.py          # CQ5: All brokers analysis
├── verify_cq5_definitive.py          # CQ5: Definitive broker analysis
├── verify_cq5_final.py               # CQ5: Final broker verification
├── verify_cq6b.py                    # CQ6b: Advanced verification
├── Challenge2 (2).pdf                # Challenge documentation
├── iot_2_Exercises.pdf               # Exercise reference materials
├── iot_Challenge2.pdf                # Additional challenge documentation
└── README.md                         # This file
```

## 🛠 Technologies & Dependencies

- **Python 3.x**: Core scripting language
- **Wireshark/tshark**: Network packet capture analysis
- **Scapy**: Packet manipulation and parsing
- **Matplotlib**: Data visualization (for CQ8)
- **Subprocess**: System command execution for tshark integration

### Prerequisites

```bash
# macOS installation of Wireshark (includes tshark)
brew install wireshark

# Python packages
pip install scapy matplotlib
```

## 🚀 Quick Start

### Running Analysis Scripts

```bash
# Analyze capture file A
python3 analyze_A.py

# Analyze capture file B
python3 analyze_B.py

# Run specific challenge solutions
python3 cq2_solve.py      # CoAP resource analysis
python3 cq3_extract.py    # Data extraction
python3 cq4_mqttsn.py     # MQTT-SN parsing
python3 cq8_plot.py       # Generate visualizations

# Verify solutions
python3 verify_cq3.py     # Verify CQ3 solution
python3 verify_cq5.py     # Verify CQ5 solution
python3 verify_cq6b.py    # Verify CQ6b solution
```

## 📊 Challenge Solutions

### CQ2: CoAP POST/PUT Analysis
Identifies CoAP resources that have equal numbers of unique unsuccessful CON POST and PUT requests to the local server.

**Files**: `cq2_solve.py`
**Dependencies**: tshark, CoAP protocol analysis

### CQ3: Data Extraction
Extracts and processes specific data patterns from network traffic.

**Files**: `cq3_extract.py`, `verify_cq3.py`
**Dependencies**: Python standard library

### CQ4: MQTT-SN Protocol
Parses and analyzes MQTT-SN messages on port 1885, including message type identification and protocol structure analysis.

**Files**: `cq4_mqttsn.py`
**Dependencies**: tshark, MQTT-SN protocol knowledge

### CQ5: Broker Analysis
Performs comprehensive broker comparison and analysis across different MQTT/CoAP implementations.

**Files**: `verify_cq5.py`, `verify_cq5_allbrokers.py`, `verify_cq5_definitive.py`, `verify_cq5_final.py`
**Dependencies**: Network protocol analysis tools

### CQ6b: Advanced Analysis
Advanced network protocol analysis with complex packet filtering and interpretation.

**Files**: `verify_cq6b.py`

### CQ8: Visualization
Generates plots and visualizations from processed network data.

**Files**: `cq8_plot.py`
**Dependencies**: matplotlib

## 🔍 Network Protocols Analyzed

- **CoAP (Constrained Application Protocol)**: Lightweight request/response protocol for IoT
- **MQTT-SN (MQTT for Sensor Networks)**: Lightweight pub/sub protocol variant
- **UDP**: Transport layer for IoT protocols
- **TCP**: For certain protocol exchanges

## 💡 Key Features

- **Packet-level Analysis**: Deep inspection of captured network traffic
- **Protocol Parsing**: Custom implementations for IoT protocol parsing
- **Verification Scripts**: Automated validation of solution correctness
- **Data Visualization**: Graphical representation of analysis results
- **Multi-broker Support**: Analysis of different MQTT/CoAP broker implementations

## 📝 Notes

- Tshark paths are configured for macOS (`/Applications/Wireshark.app/Contents/MacOS/tshark`)
- Capture files (A.pcapng, B.pcapng) are required for running analysis scripts
- Some scripts use hardcoded paths; modify as needed for your environment
- All analysis uses network packet capture files in PCAP format

## 🔧 Configuration

Key configuration variables in scripts:
```python
TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"  # Path to tshark executable
FILE_A = "/path/to/A.pcapng"                                   # Path to capture file A
FILE_B = "/path/to/B.pcapng"                                   # Path to capture file B
```

## 📚 References

- CoAP Specification: RFC 7252
- MQTT-SN Specification: ISO/IEC 20922
- Challenge Documentation: See PDF files in project directory

## ✅ Testing & Verification

All challenge solutions include corresponding verification scripts:
- Run verification scripts to validate solution correctness
- Check output against expected results in challenge documentation
- Multiple verification approaches provided for complex challenges (CQ5)

## 📄 License

This project is part of an educational IoT challenge assignment.

## 👤 Author

Network Analysis and IoT Protocol Challenge Solutions

---

**Last Updated**: 2026

**Status**: Complete challenge solution set
