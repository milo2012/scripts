import socket
from concurrent.futures import ThreadPoolExecutor
import argparse

#python3 telnet_scanner.py targets.txt --timeout 3 --threads 20 -o telnet_results.log

def check_telnet(ip, port, timeout=5, log_file=None):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            data = sock.recv(1024)
            if data:
                # Log raw bytes if a log file is provided
                if log_file:
                    with open(log_file, "a") as log:
                        log.write(f"{ip}:{port} - RAW: {repr(data)}\n")
            # Detect Telnet by IAC byte
            if b'\xff' in data:
                return f"{ip}:{port} likely Telnet"
    except Exception:
        pass
    return None

def scan_list(ip_port_list, timeout=5, max_threads=10, log_file=None):
    results = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(check_telnet, ip, port, timeout, log_file) for ip, port in ip_port_list]
        for future in futures:
            result = future.result()
            if result:
                results.append(result)
    return results

def load_ip_ports(file_path):
    ip_port_list = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if ':' in line:
                ip, port = line.split(':')
                ip_port_list.append((ip, int(port)))
    return ip_port_list

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect Telnet services by raw socket connection.")
    parser.add_argument("input_file", help="File with IP:PORT entries (one per line)")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout per connection (default: 5s)")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    parser.add_argument("-o", "--output", type=str, help="Output file to log results")
    args = parser.parse_args()

    targets = load_ip_ports(args.input_file)
    results = scan_list(targets, timeout=args.timeout, max_threads=args.threads, log_file=args.output)

    print("\nPossible Telnet Services Detected:")
    for entry in results:
        print(entry)

    # If no output file is specified, create one with default name
    if args.output:
        print(f"\nLog saved to {args.output}")
    else:
        print("\nNo output log specified.")
