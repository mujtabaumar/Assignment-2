
---

````markdown
# Network Packet Analyzer
### DSA - Assignment 2  
### Mujtaba Umar, BSDS-2A

---

## Overview
This project is a simple network packet analyzer built entirely from scratch without using any STL containers.  
It captures live network traffic, stores it using custom data structures, and breaks down packets into their protocol layers for analysis.

---

## Program Description
The analyzer continuously listens on a chosen network interface and processes packets using custom-built **Queue** and **Stack** data structures.  
- The **Queue** (FIFO) manages captured, filtered, and backup packets.  
- The **Stack** (LIFO) is used to decode protocol layers in reverse order.  

Supported protocols: **Ethernet**, **IPv4**, **IPv6**, **TCP**, and **UDP**.  
Packets can be filtered by IP address and replayed with retries in case of transmission failure.

---

## Features

### Packet Capture
- Captures packets in real-time from the specified network interface.  
- Uses raw sockets (requires root privileges).  

### Custom Queue (FIFO)
- Implemented with a linked list.  
- Functions: `enqueue()`, `dequeue()`, `isEmpty()`, `size()`.  
- Handles all captured and filtered packets.  

### Custom Stack (LIFO)
- Implemented manually using linked nodes.  
- Functions: `push()`, `pop()`, `peek()`, `isEmpty()`.  
- Used for dissecting packet layers (Ethernet → IP → TCP/UDP).  

### Packet Structure
Each packet contains:
- Unique packet ID  
- Timestamp  
- Raw packet data  
- Source and destination IP addresses  
- Retry count  

### Protocol Dissection
Information extracted from each layer includes:
- **Ethernet:** Source/Destination MAC, EtherType  
- **IPv4 / IPv6:** IP addresses, TTL, protocol value  
- **TCP:** Ports, sequence and acknowledgment numbers, flags  
- **UDP:** Ports and datagram length  

### Filtering
- Filter packets by source and destination IPs.  
- Skips oversized packets (>1500 bytes) after threshold is reached.  
- Adds replay delay calculated as `packet_size / 1000 ms`.  

### Replay with Error Handling
- Sends filtered packets through the same interface.  
- Retries up to two times on failure.  
- Uses a backup queue for retry management.

---

## Requirements
- Linux operating system  
- Root privileges (for raw sockets)  
- `g++` compiler  

---

## Compilation
```bash
g++ -o network_monitor main.cpp -std=c++11
````

---

## Running the Program

```bash
sudo ./network_monitor
```

By default, the program captures packets for **60 seconds** and displays results afterward.

---

## Configuration

The default interface is the loopback (`lo`).
To change it, open **main.cpp** and update this line (around line 450):

```cpp
const char* interface = "lo";
```

To list all available interfaces:

```bash
ip link show
```

---

## Testing

Generate traffic while the analyzer runs:

```bash
ping 127.0.0.1 -c 100
```

---

## Key Highlights

* Custom **Queue** and **Stack** (no STL containers).
* Manual parsing of Ethernet, IP, TCP, and UDP headers.
* Filtering and replay functionality.
* Retry mechanism for failed transmissions.
* Memory-safe management of raw packet buffers.

---

## Assumptions

* Single network interface is used.
* Root access available for socket operations.
* Linux-based system.
* Network activity exists during capture.
* Maximum of 2 retries per failed packet.

---

## File List

| File         | Description              |
| ------------ | ------------------------ |
| `main.cpp`   | Main program source code |
| `README.md`  | Project documentation    |
| `Report.pdf` | Project report           |

---

## Notes

The hardest part was decoding IPv6 headers correctly and managing memory safely when copying raw packet data.
Using a **Queue** for packet management and a **Stack** for protocol parsing mirrors how network stacks work internally.
The project demonstrates the integration of data structures with raw socket programming in C++.

---

## GitHub Repository



```

---

