import sys
import socket
import re
import argparse
import os

def build_client_hello(hostname):
    svn_url = f"svn://{hostname}"
    return f"( 2 ( edit-pipeline ) {len(svn_url)}:{svn_url} 6:Nessus ( ) )\n"

def check_svn_auth(host, port, timeout, detailed):
    if detailed:
        print(f"[+] Connecting to {host}:{port} with timeout {timeout}s...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, int(port)))

            banner = s.recv(2048).decode(errors='ignore').strip()
            if detailed:
                print(f"[+] Received banner: {banner}")

            match = re.search(r"\(\s*success\s*\(\s*(\d+)\s+(\d+)", banner)
            if not match:
                if detailed:
                    print("[-] Could not parse version info from banner.")
                else:
                    print(f"{host}:{port} - Could not parse version info from banner.")
                return
            min_ver, max_ver = int(match.group(1)), int(match.group(2))
            if detailed:
                print(f"[+] SVN supports protocol version: {min_ver} to {max_ver}")

            if min_ver > 2 or max_ver < 2:
                if detailed:
                    print("[-] Server does not support required protocol version (2).")
                else:
                    print(f"{host}:{port} - Server does not support required protocol version (2).")
                return

            client_hello = build_client_hello(host)
            s.send(client_hello.encode())
            response = s.recv(2048).decode(errors='ignore').strip()

            if not response:
                if detailed:
                    print("[-] No response received from server after sending client hello.")
                else:
                    print(f"{host}:{port} - No response received from server after sending client hello.")
                return

            if detailed:
                print(f"[+] Received response:\n{response}")

            match = re.search(r"\(\s*success\s*\(\s*\(([^()]*)\)", response)
            if not match:
                if detailed:
                    print("[-] Could not find SASL mechanism list in response.")
                else:
                    print(f"{host}:{port} - Could not find SASL mechanism list in response.")
                return

            mechs = match.group(1)
            if detailed:
                print(f"[+] Server supports SASL mechanisms: {mechs}")

            cleartext_mechs = [m for m in ["PLAIN", "LOGIN"] if m in mechs]
            if cleartext_mechs:
                if detailed:
                    print(f"[!] Cleartext authentication supported: {mechs}")
                else:
                    print(f"{host}:{port} - Cleartext authentication supported: {' '.join(cleartext_mechs)}")
            else:
                if detailed:
                    print("[+] No cleartext authentication mechanisms found.")
                else:
                    print(f"{host}:{port} - No cleartext authentication mechanisms found.")
    except Exception as e:
        if detailed:
            print(f"[ERROR] {host}:{port} - {e}")
        else:
            print(f"{host}:{port} - ERROR: {e}")

def process_file(filename, timeout, detailed):
    if not os.path.isfile(filename):
        print(f"[ERROR] File not found: {filename}")
        return

    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            host, port = line.split(":", 1)
            check_svn_auth(host.strip(), port.strip(), timeout, detailed)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SVN cleartext auth detector")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--host", help="Target host in format host:port")
    group.add_argument("-f", "--file", help="File with list of targets in host:port format (one per line)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Socket timeout in seconds (default: 5)")
    parser.add_argument("-d", "--detailed", action="store_true", help="Show detailed output")

    args = parser.parse_args()

    if args.host:
        if ":" not in args.host:
            print("[ERROR] --host must be in host:port format")
            sys.exit(1)
        host, port = args.host.split(":", 1)
        check_svn_auth(host.strip(), port.strip(), args.timeout, args.detailed)
    elif args.file:
        process_file(args.file, args.timeout, args.detailed)
