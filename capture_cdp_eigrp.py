from scapy.all import *
import argparse
import sys

def packet_callback(pkt):
    try:
        # Check for CDP packets (Ethernet type 0x2000)
        if pkt.haslayer(Ether) and pkt[Ether].type == 0x2000:
            print("=" * 50)
            print("CDP Packet Detected:")
            print(f"Source MAC: {pkt[Ether].src}")
            print(f"Destination MAC: {pkt[Ether].dst}")
            print(f"Packet Summary: {pkt.summary()}")
            
            # Try to parse CDP layer if available
            try:
                # CDP parsing might need custom implementation
                # as Scapy's CDP support can be limited
                raw_data = bytes(pkt[Ether].payload)
                print(f"CDP Raw Data (first 64 bytes): {raw_data[:64].hex()}")
            except Exception as e:
                print(f"CDP parsing error: {e}")
            print()
            
        # Check for EIGRP packets (IP protocol number 88)
        elif pkt.haslayer(IP) and pkt[IP].proto == 88:
            print("=" * 50)
            print("EIGRP Packet Detected:")
            print(f"Source IP: {pkt[IP].src}")
            print(f"Destination IP: {pkt[IP].dst}")
            print(f"TTL: {pkt[IP].ttl}")
            print(f"Packet Summary: {pkt.summary()}")
            
            # Extract EIGRP payload
            try:
                eigrp_payload = bytes(pkt[IP].payload)
                print(f"EIGRP Payload (first 32 bytes): {eigrp_payload[:32].hex()}")
                
                # Basic EIGRP header parsing
                if len(eigrp_payload) >= 20:
                    version = eigrp_payload[0]
                    opcode = eigrp_payload[1]
                    checksum = int.from_bytes(eigrp_payload[2:4], 'big')
                    flags = int.from_bytes(eigrp_payload[4:8], 'big')
                    sequence = int.from_bytes(eigrp_payload[8:12], 'big')
                    ack = int.from_bytes(eigrp_payload[12:16], 'big')
                    vrid = int.from_bytes(eigrp_payload[16:20], 'big')
                    asn = int.from_bytes(eigrp_payload[20:22], 'big') if len(eigrp_payload) >= 22 else 0
                    
                    print(f"EIGRP Version: {version}")
                    print(f"EIGRP Opcode: {opcode}")
                    print(f"EIGRP Flags: 0x{flags:08x}")
                    print(f"EIGRP Sequence: {sequence}")
                    print(f"EIGRP ACK: {ack}")
                    print(f"EIGRP AS Number: {asn}")
                    
            except Exception as e:
                print(f"EIGRP parsing error: {e}")
            print()
            
    except Exception as e:
        print(f"Packet processing error: {e}")

def list_interfaces():
    """Display available network interfaces"""
    print("Available network interfaces:")
    interfaces = get_if_list()
    for i, iface in enumerate(interfaces, 1):
        print(f"  {i}. {iface}")
    return interfaces

def main():
    parser = argparse.ArgumentParser(
        description="Capture and analyze CDP and EIGRP network packets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python script.py -i eth0                    # Capture on eth0 interface
  python script.py --interface wlan0         # Capture on wlan0 interface
  python script.py --list                    # List available interfaces
  python script.py -i eth0 --verbose         # Capture with verbose output
        """
    )
    
    parser.add_argument('-i', '--interface', 
                       help='Network interface to capture packets on (e.g., eth0, wlan0, en0)')
    parser.add_argument('--list', action='store_true',
                       help='List available network interfaces and exit')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # If --list flag is used, show interfaces and exit
    if args.list:
        list_interfaces()
        sys.exit(0)
    
    # Get available interfaces
    available_interfaces = get_if_list()
    
    # Determine which interface to use
    if args.interface:
        if args.interface not in available_interfaces:
            print(f"Error: Interface '{args.interface}' not found.")
            print("\nAvailable interfaces:")
            for iface in available_interfaces:
                print(f"  - {iface}")
            sys.exit(1)
        iface = args.interface
    else:
        # If no interface specified, show available ones and prompt
        print("No interface specified. Available interfaces:")
        interfaces = list_interfaces()
        print("\nPlease specify an interface using -i/--interface option")
        print("Example: python script.py -i eth0")
        sys.exit(1)
    
    # BPF filter for CDP and EIGRP packets
    bpf_filter = "ether proto 0x2000 or ip proto 88"
    
    print(f"Starting packet capture on interface: {iface}")
    print(f"Filter: {bpf_filter}")
    if args.verbose:
        print("Verbose mode: ON")
    print("Press Ctrl+C to stop capture...")
    print("-" * 60)
    
    try:
        # Start packet capture
        sniff(iface=iface, filter=bpf_filter, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except PermissionError:
        print("Permission denied. Try running with sudo (Linux/macOS) or as Administrator (Windows)")
        sys.exit(1)
    except Exception as e:
        print(f"Capture error: {e}")
        print("Make sure:")
        print("1. You're running with appropriate privileges (sudo on Linux/macOS)")
        print("2. The specified interface exists and is active")
        print("3. No other packet capture tools are using the interface")

if __name__ == "__main__":
    main()