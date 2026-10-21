import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

from scapy.all import (
    sniff,
    wrpcap,
    get_if_list,
    IP,
    TCP,
    UDP,
    ICMP,
    ARP,
    DNS,
)
from scapy.layers.inet6 import IPv6

# Store packets for export when capture finishes.
captured_packets = []
packet_count = 0


def ensure_capture_permissions():
    """Relaunch with administrator privileges on macOS."""
    if sys.platform == "darwin" and os.geteuid() != 0:
        print("Packet capture requires administrator privileges.")
        print("Requesting macOS authorization...\n")

        script_path = os.path.abspath(__file__)

        os.execvp(
            "sudo",
            [
                "sudo",
                sys.executable,
                script_path,
                *sys.argv[1:],
            ],
        )


def identify_protocol(packet):
    """Identify the most relevant protocol in a packet."""

    if ARP in packet:
        return "ARP"

    # Recognize specific and unknown ICMPv6 message classes.
    if any(layer.__name__.startswith("ICMPv6") for layer in packet.layers()):
        return "ICMPv6"

    if ICMP in packet:
        return "ICMP"

    if TCP in packet:
        return "TCP"

    if UDP in packet and DNS in packet:
        return "DNS"

    if UDP in packet:
        return "UDP"

    if IPv6 in packet:
        return "IPv6"

    if IP in packet:
        return "IPv4"

    return "Other"


def process_packet(packet):
    """Display useful metadata for a captured packet."""
    global packet_count

    packet_count += 1
    captured_packets.append(packet)

    timestamp = datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S.%f")[:-3]

    source = "Unknown"
    destination = "Unknown"
    source_port = "-"
    destination_port = "-"

    # Extract network-layer addresses.
    if IP in packet:
        source = packet[IP].src
        destination = packet[IP].dst

    elif IPv6 in packet:
        source = packet[IPv6].src
        destination = packet[IPv6].dst

    elif ARP in packet:
        source = packet[ARP].psrc
        destination = packet[ARP].pdst

    # Extract transport-layer ports.
    if TCP in packet:
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    protocol = identify_protocol(packet)

    print(
        f"{packet_count:05d} | {timestamp} | "
        f"{protocol:7} | "
        f"{source}:{source_port} -> "
        f"{destination}:{destination_port} | "
        f"{len(packet)} bytes"
    )


def build_filter(protocol, host):
    """Build a Berkeley Packet Filter expression."""
    filters = []

    if protocol != "all":
        filters.append(protocol)

    if host:
        filters.append(f"host {host}")

    return " and ".join(filters) if filters else None


def main():
    parser = argparse.ArgumentParser(
        description="A beginner-friendly macOS packet sniffer."
    )

    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces.",
    )

    parser.add_argument(
        "--iface",
        default="en0",
        help="Network interface to capture from (default: lo0).",
    )

    parser.add_argument(
        "--protocol",
        choices=[
            "all",
            "tcp",
            "udp",
            "icmp",
            "icmp6",
            "arp",
            "ip",
            "ip6",
        ],
        default="all",
        help="Protocol filter (default: all).",
    )

    parser.add_argument(
        "--host", default=None, help="Capture packets involving this IP address."
    )

    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Stop after this many packets; 0 means unlimited.",
    )

    parser.add_argument(
        "--output", default="website-test.pcap", help="PCAP output filename."
    )

    args = parser.parse_args()

    if args.count < 0:
        parser.error("--count cannot be negative")

    # Interface discovery does not require packet capture.
    if args.list_interfaces:
        print("\n".join(get_if_list()))
        return

    # Validate the interface before requesting elevated privileges.
    if args.iface not in get_if_list():
        parser.error(
            f"Interface '{args.iface}' not found. "
            "Use --list-interfaces to see available interfaces."
        )

    # Request administrator authorization before capturing.
    ensure_capture_permissions()

    bpf_filter = build_filter(
        args.protocol,
        args.host,
    )

    print("Packet Sniffer v1.1")
    print(f"Interface : {args.iface}")
    print(f"Filter    : {bpf_filter or 'None'}")
    print(f"Packet cap: {args.count or 'Unlimited'}")
    print("Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=args.iface,
            filter=bpf_filter,
            prn=process_packet,
            store=False,
            count=args.count,
        )

    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")

    except Exception as error:
        print(f"\nCapture error: {error}")

    finally:
        if captured_packets:
            output_path = Path(args.output).expanduser().resolve()

            try:
                output_path.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                wrpcap(
                    str(output_path),
                    captured_packets,
                )

                print(f"\nPackets captured: {packet_count}")
                print(f"Capture saved to: {output_path}")

                if os.geteuid() == 0:
                    print("Note: the capture file may be owned by root.")

            except Exception as error:
                print(f"\nCould not save capture: {error}")

        else:
            print("\nNo packets captured; no PCAP file written.")


if __name__ == "__main__":
    main()
