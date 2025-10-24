#!/usr/bin/env python3
import argparse
import requests
import sys

def decode_bigip_cookie(cookie_value: str):
    """Decode F5 BIG-IP cookie value into IP:Port."""
    try:
        parts = cookie_value.split('.')
        if len(parts) < 2:
            return "Invalid cookie format"

        # Decode IP
        ip_num = int(parts[0])
        ip_hex = f"{ip_num:08x}"
        ip_bytes = [ip_hex[i:i+2] for i in range(0, 8, 2)][::-1]
        ip_addr = '.'.join(str(int(b, 16)) for b in ip_bytes)

        # Decode Port
        port_num = int(parts[1])
        port_hex = f"{port_num:04x}"
        port_bytes = [port_hex[i:i+2] for i in range(0, 4, 2)][::-1]
        port = int(''.join(port_bytes), 16)

        return f"{ip_addr}:{port}"
    except Exception as e:
        return f"Decode error: {e}"

def check_url(url: str):
    try:
        resp = requests.get(url, timeout=5, verify=False)
        cookie_value = resp.cookies.get("BIGipServerportals_pool")
        if cookie_value:
            decoded = decode_bigip_cookie(cookie_value)
            print(f"{url} → {decoded}")
        else:
            print(f"{url} → No BIGipServerportals_pool cookie found")
    except Exception as e:
        print(f"{url} → Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Check and decode F5 BIG-IP cookies from a URL")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com)")
    args = parser.parse_args()

    # Disable warnings for self-signed SSL
    requests.packages.urllib3.disable_warnings()
    
    check_url(args.url)

if __name__ == "__main__":
    main()

