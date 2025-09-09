# PacketSniffer

A simple network packet sniffer written in C++ that captures network packets on a specified interface, applies a filter (like `"tcp or udp or icmp"`), and exports captured packet information as JSON lines to a file.

---

## Features

- Captures packets on any network interface you specify
- Supports packet filtering using [libpcap](https://www.tcpdump.org/manpages/pcap-filter.7.html) syntax
- Extracts packet details such as source/destination IP, ports, protocol, and packet size
- Exports captured packets in JSON format for easy processing or analysis
- Uses [`nlohmann-json`](https://github.com/nlohmann/json) library for JSON serialization

---

## Requirements

- Linux-based OS (Ubuntu or similar)
- `libpcap-dev` installed
- `pkg-config` installed
- `nlohmann-json3-dev` installed
- C++ compiler supporting C++11 or later
- CMake (for building)

---

## Installation

Install dependencies on Ubuntu:

```bash
sudo apt update
sudo apt install build-essential cmake libpcap-dev pkg-config nlohmann-json3-dev

---

## Building

mkdir build
cd build
cmake ..
make

---

## Usage
sudo ./packet_sniffer <interface> <output.json> "<filter>"

---

## Running

sudo ./packet_sniffer eth0 packets.json "tcp or udp or icmp"

---


## Output

{
  "src_ip": "192.168.1.10",
  "src_port": 443,
  "dst_ip": "10.0.0.5",
  "dst_port": 53124,
  "protocol": 6,
  "size": 1500
}
---
