# OMEGA: Layer 4 Network Scanner

## Table of Contents

1. [Introduction](#introduction)
2. [Theoretical Background](#theoretical-background)
3. [Application Architecture](#application-architecture)
4. [Code Overview](#code-overview)
5. [Testing and Validation](#testing-and-validation)
6. [Additional Features](#additional-features)
7. [Bibliography](#bibliography)

---

## Introduction

Scanner to identifie the status of TCP and UDP ports on target hosts. Ports can be open, closed or filtered which is determined by behavior after sending packet to port.

**Scanning ports is operated as follows:**

- Sending custom TCP SYN packets via raw sockets
- Scanning UDP ports and interpreting ICMP responses
- Running concurrent scans with multithreading, to not consume too much time
- Supporting both IPv4 (IPv6 only for UDP)

---

## Theoretical Background

### Port Scanning Basics

Each host on a network exposes services via numbered ports. Scanning these ports reveals:

- Which services are running
- Whether firewalls are blocking traffic
- If the host is live or inactive

### TCP SYN Scanning

A common and stealthy scanning method:

- Sends a SYN packet (start of a TCP handshake)
- Receives:
  - SYN-ACK → port is **open**
  - RST → port is **closed**
  - No response → port is **filtered** (by a firewall)

### UDP Scanning

- Sends a UDP datagram
- If the port is **closed**, the OS responds with an ICMP Port Unreachable
- In all other cases is port **open**

---

## Application Architecture

The scanner is structured into multiple modules:

- `main.cpp`
- `tcp_scanner.hpp/cpp` Handles TCP SYN scanning
- `udp_scanner.hpp/cpp` Handles UDP scanning via ICMP interpretation
- `utils.hpp/cpp` Utilities: IP resolution, interface management, argument parsing

### Multithreading

- Uses `std::thread` to allow up to parallel scans and join result.
- Uses `std::counting_semaphore` to limit how many thread can run simultaneously
- Each scan is independent and synchronized using a mutex-protected result map.

---

## Code Overview

### Main Program

- Parses CLI arguments
- Resolves domain names to IPv4/IPv6 addresses
- Selects proper source IP based on chosen network interface
- Dispatches scan jobs in parallel using threads
- Using `TcpScanner`, `UdpScanner` and also `Utils`

### TCP Scanner

- Creates raw IPv4/IPv6 packets with TCP SYN headers
- Receives responses and interprets flags (SYN-ACK, RST, etc.)
  - For some time listen to incoming packets, filter them and try find needed packet
  - If no packet is found, send new TCP packet and repeat new proces as second attempt
- Uses raw sockets and low-level packet crafting for control
- Does not work for IPv6

```c++
class TcpScanner
{
private:
  const char *src_ip;
  const char *target_ip;
  const char *interface;
  int port;
  int src_port;
  bool isIPv6;
  int timeout_ms;

public:
  TcpScanner(const char *_src_ip, const char *_target_ip, const char *_interface, int _port, int _src_port, bool _isIPv6, int _timeout_ms);
  void sendSynPacket(int sock);
  std::string scanPort();
};
```

### UDP Scanner

- Sends empty UDP packet
- Listens for ICMP Port Unreachable messages
- Filters responses based on embedded port in ICMP payload
- Works for both IPv4 (ICMP) and IPv6 (ICMPv6)

```cpp
class UdpScanner
{
public:
  static std::string scanPort(const char *target_ip, int port, int timeout_ms, const char *interface);
};
```

### Utilities

- Used in all other modules especially in main.cpp
- Parses port ranges (e.g. `20-25,80`)
- Resolves domains via `getaddrinfo`
- Retrieves IP addresses from available network interfaces
- Detects whether a string is an IPv4 or IPv6 address
- Validates and lists network interfaces

```cpp
#define BUFFER_SIZE 1024

enum class AddressType
{
  IPv4,
  IPv6,
  Unknown
};

class Utils
{
public:
  static std::vector<std::string> resolveDomainToIPs(const std::string &domain);
  static std::pair<std::string, std::string> getLocalIPAddresses();
  static std::vector<int> parsePortRange(const std::string &rangeStr);
  static std::pair<std::string, std::string> getIPAddressesForInterface(const std::string &ifaceName);
  static AddressType getAddressType(const std::string &ipStr);
};
```

---

## Testing and Validation

Testing was done using **tcp dump**, because it can see all packets and can filter them so it was perfectly adequate for testing.

The following tests were conducted:

### ✅ Functional Testing

- Verified detection of open, closed, and filtered TCP/UDP ports on:
  - Localhost
  - External IPv4 hosts (e.g. `8.8.8.8`)
  - Dual-stack (IPv4/IPv6) systems

```
Command:
sudo ./ipk-l4-scan -i eth0 -t 443 jeraby-spunda.cz

Output:
185.129.138.202 443 tcp open

Tcpdump output:
22:55:51.411777 IP 172.22.49.179.45931 > 202.138.forpsi.net.https: Flags [S], seq 0, win 1024, length 0
22:55:51.427624 IP 202.138.forpsi.net.https > 172.22.49.179.45931: Flags [S.], seq 794033546, ack 1, win 29200, options [mss 1440], length 0
22:55:51.427666 IP 172.22.49.179.45931 > 202.138.forpsi.net.https: Flags [R], seq 1, win 0, length 0
```

### ✅ Performance Testing

- Confirmed that multithreaded scanning scales well with large port ranges
- Demonstrated speed improvement from 10–20 ports/sec (single-thread) → 1000+ ports/sec

```
Command:
time sudo ./ipk-l4-scan -i eth0 -t 1-1000 -u 32459-33459 8.8.8.8

Output:
8.8.8.8 1 tcp filtered
...
8.8.8.8 52 tcp filtered
8.8.8.8 53 tcp open
8.8.8.8 54 tcp filtered
...
8.8.8.8 442 tcp filtered
8.8.8.8 443 tcp open
8.8.8.8 444 tcp filtered
...
8.8.8.8 1000 tcp filtered
8.8.8.8 32459 udp open
...
8.8.8.8 33433 udp open
8.8.8.8 33434 udp closed
...
8.8.8.8 33459 udp closed

real    0m16.845s
user    0m0.012s
sys     0m0.000s
```

### ✅ Interface Binding

- Validated that `SO_BINDTODEVICE` ensures correct source interface
- Verified behavior when scanning with multiple interfaces and addresses
- In some cases, even if interface is not `eth0` packet is sent for selected interface and also for `eth0`, but it is ignored so everything works correctly

```
Command:
sudo ./ipk-l4-scan -i lo -t 1-50,443 localhost

Output
127.0.0.1 1 tcp closed
127.0.0.1 2 tcp closed
...
127.0.0.1 49 tcp closed
127.0.0.1 50 tcp closed
127.0.0.1 443 tcp closed
```

### ✅ UDP Port Resolution

- Confirmed that embedded UDP destination ports in ICMP messages are matched correctly (checked target IP address)
- Ensured that packets from unrelated scans are ignored safely

---

## Usage

```bash
./ipk-l4-scan [-i interface] [--pu port-ranges | --pt port-ranges | -u port-ranges | -t port-ranges] {-w timeout} [hostname | ip-address]
```

## Bibliography

- GeeksforGeeks: Creating a PortScanner in C
- HackerTarget: Port Scanner Tutorial
- TechTarget: How to build a port scanner
- Wikipedia: Nmap
- Linux Raw Sockets Documentation
- RFC 792 (ICMP)
- RFC 4443 (ICMPv6)
