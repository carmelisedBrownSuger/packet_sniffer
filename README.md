# Packet Sniffer

A command-line packet sniffer built with **Python** and **Scapy**. It captures live traffic on a selected network interface, prints useful packet metadata, supports basic protocol/host filters, and can export captured packets to a PCAP file for inspection in Wireshark.

> **Authorization:** Use this tool only on systems and networks you own or have explicit permission to monitor. Packet captures can contain sensitive information. Do not publish captures containing private traffic.

## Features

- Live packet capture through Scapy.
- Recognizes ARP, TCP, UDP, DNS, ICMP, ICMPv6, IPv4, and IPv6.
- Prints timestamp, protocol, source/destination addresses, TCP/UDP ports when present, and packet length.
- Selects a network interface and filters by protocol or host.
- Stops after a requested packet count or with `Ctrl+C`.
- Exports captured packets to PCAP for verification and further analysis in Wireshark.
- Includes platform-specific setup and permission guidance.

## Requirements

- Python 3.10 or newer is recommended.
- Scapy and a supported packet-capture backend.
- Administrator/root privileges or the relevant packet-capture permissions.
- Wireshark is optional; it is useful for inspecting the exported PCAP.

## Installation

Clone the repository, then enter its directory:

```bash
git clone https://github.com/YOUR-USERNAME/packet-sniffer.git
cd packet-sniffer
```

Create and activate a virtual environment.

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, you can invoke the environment's Python directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Packet-capture permissions by operating system

### macOS

Packet capture usually requires administrator privileges. This script detects an unprivileged macOS run and relaunches itself through `sudo`, which prompts for your password.

```bash
python packet_sniffer.py --list-interfaces
route -n get default | grep interface
sudo -v
python packet_sniffer.py --iface en0 --output captures/website-test.pcap
```

Replace `en0` with the interface reported by the route command. Wi-Fi is often `en0`, but interface names vary. The script's `sudo` relaunch may cause the output PCAP to be owned by root; if so, change ownership or permissions locally before moving or deleting the file.

### Linux

Use `--list-interfaces` to identify the correct interface. Names may look like `eth0`, `ens33`, or `wlan0`.

```bash
python packet_sniffer.py --list-interfaces
sudo .venv/bin/python packet_sniffer.py --iface eth0 --output captures/test.pcap
```

Replace `eth0` with your actual interface. `sudo` is used here because packet capture commonly requires elevated privileges. If you use a virtual environment, run its Python interpreter explicitly as shown.

### Windows

Install **Npcap** from the official Nmap/Npcap website. During installation, enable the option to support WinPcap API-compatible applications if offered. Then open PowerShell or Terminal **as Administrator**, activate the virtual environment, and run:

```powershell
python packet_sniffer.py --list-interfaces
python packet_sniffer.py --iface "Ethernet" --output captures/test.pcap
```

Replace `Ethernet` with an interface name printed by the script. Names vary; Wi-Fi might have a different name. Scapy's packet capture on Windows depends on a working Npcap installation. If capture fails, confirm Npcap is installed and the terminal is elevated.

## Usage

### List interfaces

```bash
python packet_sniffer.py --list-interfaces
```

### Capture on a specific interface

```bash
python packet_sniffer.py --iface en0 --output captures/capture.pcap
```

Use the relevant privilege method for your operating system.

### Capture only TCP traffic

```bash
python packet_sniffer.py --iface en0 --protocol tcp --output captures/tcp.pcap
```

### Capture traffic involving a host

```bash
python packet_sniffer.py --iface en0 --host 192.0.2.10 --output captures/host.pcap
```

Use an IP address that is valid for your own test environment. `192.0.2.10` is an example documentation address.

### Combine protocol and host filters

```bash
python packet_sniffer.py --iface en0 --protocol tcp --host 192.0.2.10 --output captures/host-tcp.pcap
```

### Stop after 100 packets

```bash
python packet_sniffer.py --iface en0 --count 100 --output captures/first-100.pcap
```

### Capture all supported traffic until interrupted

```bash
python packet_sniffer.py --iface en0 --protocol all --output captures/all-traffic.pcap
```

Press `Ctrl+C` to stop. The program writes captured packets to the selected PCAP path when capture ends.

## Verify a capture with Wireshark

1. Run the sniffer and generate authorized test traffic, such as visiting a website or running `curl -I https://example.com` in another terminal.
2. Stop the capture with `Ctrl+C` if no packet count was specified.
3. Open the resulting `.pcap` file in Wireshark.
4. Compare the packet timestamps, addresses, protocols, and ports with the command-line output.

If no packets appear, check that you selected the active interface. The loopback interface (often `lo0` on macOS) captures local-host traffic, not ordinary traffic routed over Wi-Fi. A VPN may change the active route or interface. Start with `--protocol all` before narrowing the filter.

## Command-line options

| Option | Purpose |
| --- | --- |
| `--list-interfaces` | Print available interfaces and exit |
| `--iface NAME` | Interface to capture on |
| `--protocol PROTOCOL` | One of `all`, `tcp`, `udp`, `icmp`, `icmp6`, `arp`, `ip`, `ip6` |
| `--host IP` | Filter traffic involving a host IP |
| `--count N` | Stop after N packets; `0` means unlimited |
| `--output PATH` | PCAP output path; defaults to `capture.pcap` |

Run `python packet_sniffer.py --help` for the built-in help.

## Limitations

- HTTPS/TLS payloads are generally encrypted. This tool displays packet metadata; it does not decrypt website content.
- The program retains captured packets in memory until it writes the PCAP file. Very long captures can consume substantial memory.
- Capturing on a normal Wi-Fi interface generally shows traffic available to the local machine, not all traffic from every device on the network.
- BPF filter support depends on the installed packet-capture backend.
- Protocol identification is a simple label for display, not a full protocol-dissection or intrusion-detection engine.
- Interface names and privilege requirements differ by operating system and configuration.


