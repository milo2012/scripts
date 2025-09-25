#!/usr/bin/env python3
import subprocess
import tempfile
import os
import shutil
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
from urllib.parse import urlparse
import sys
import platform

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

DEFAULT_EXE_PATH = "/epa/scripts/win/nsepa_setup.exe"

# ANSI colors for terminal
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

def check_dependencies():
    missing = []
    if not shutil.which("cabextract"):
        missing.append("cabextract")
    if not shutil.which("msiinfo"):
        missing.append("msiinfo")

    if missing:
        os_name = platform.system()
        print(f"{RED}Missing dependencies:{RESET} {', '.join(missing)}")
        print("Please install them manually:")

        if os_name == "Darwin":
            # macOS
            if "cabextract" in missing:
                print("  brew install cabextract")
            if "msiinfo" in missing:
                print("  brew install msitools")
        elif os_name == "Linux":
            # Linux (default Debian/Ubuntu)
            if "cabextract" in missing:
                print("  sudo apt update && sudo apt install cabextract")
            if "msiinfo" in missing:
                print("  sudo apt update && sudo apt install msitools")
        else:
            # Windows or unknown OS
            print("  Please manually install cabextract and msitools for your OS")

        sys.exit(1)

def normalize_url(url):
    """Append default EXE path if URL does not end with .exe"""
    url = url.strip()
    if not url.lower().endswith(".exe"):
        url = url.rstrip("/") + DEFAULT_EXE_PATH
    return url

def download_to_temp(url):
    tmp_file = tempfile.NamedTemporaryFile(delete=False)
    parsed_url = urlparse(url)
    display_url = f"{parsed_url.scheme}://{parsed_url.netloc}"  # only scheme + host + port
    try:
        # HEAD request first
        head = requests.head(url, verify=False, allow_redirects=True)
        if head.status_code != 200:
            print(f"URL not reachable: {display_url} ({head.status_code})")
            return None

        content_type = head.headers.get("Content-Type", "").lower()
        if content_type != "application/x-msdownload":
            print(f"Skipping {display_url}: Not a Citrix Netscaler")
            return None

        # GET request to download
        resp = requests.get(url, stream=True, verify=False)
        resp.raise_for_status()
        for chunk in resp.iter_content(chunk_size=8192):
            if chunk:
                tmp_file.write(chunk)
        tmp_file.close()
        return tmp_file.name

    except Exception as e:
        tmp_file.close()
        os.unlink(tmp_file.name)
        print(f"Error downloading {display_url}: {e}")
        return None

def extract_msi_from_exe(exe_path):
    tmp_dir = tempfile.mkdtemp()
    try:
        subprocess.run(["cabextract", "-d", tmp_dir, exe_path], check=True, capture_output=True)
        for f in os.listdir(tmp_dir):
            if f.lower().endswith(".msi"):
                return os.path.join(tmp_dir, f)
    except subprocess.CalledProcessError as e:
        print(f"Error extracting CAB: {e}")
    return None

def get_msi_product_version(msi_path):
    try:
        output = subprocess.check_output(
            ["msiinfo", "export", msi_path, "Property"],
            text=True
        )
        lines = output.splitlines()[1:]  # skip header
        for line in lines:
            if not line.strip():
                continue
            parts = line.split("\t", 1)
            if len(parts) == 2 and parts[0].strip() == "ProductVersion":
                return parts[1].strip()
    except Exception as e:
        print(f"Error reading MSI: {e}")
    return None

def get_product_version_from_exe_url(url):
    url_full = normalize_url(url)
    exe_path = download_to_temp(url_full)
    if not exe_path:
        return (url, "Not found")

    try:
        msi_path = extract_msi_from_exe(exe_path)
        if not msi_path:
            return (url, "Not found")
        version = get_msi_product_version(msi_path)
        return (url, version if version else "Not found")
    finally:
        if os.path.exists(exe_path):
            os.unlink(exe_path)

def main():
    check_dependencies()  # Ensure cabextract and msiinfo exist

    parser = argparse.ArgumentParser(description="Extract MSI ProductVersion from EXE URLs")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Single URL to EXE")
    group.add_argument("-f", "--file", help="File containing URLs (one per line)")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of threads (default 4)")
    args = parser.parse_args()

    urls = []
    if args.url:
        urls = [args.url]
    elif args.file:
        with open(args.file, "r") as f:
            urls = [line.strip() for line in f if line.strip()]

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {executor.submit(get_product_version_from_exe_url, url): url for url in urls}
        for future in as_completed(future_to_url):
            results.append(future.result())

    # Professional formatted output with brackets and color
    for url, version in results:
        parsed = urlparse(url)
        display_url = f"{parsed.scheme}://{parsed.netloc}"

        if version != "Not found":
            print(f"{GREEN}[{display_url}] [Citrix NetScaler] [v{version}]{RESET}")
        else:
            print(f"{YELLOW}[{display_url}] [Not found]{RESET}")

if __name__ == "__main__":
    main()
