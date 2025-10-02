#!/usr/bin/env python3
import argparse
import os
import shutil
import subprocess
import tempfile
import sys

def run_binwalk_extract(firmware, extract_dir):
    """Use binwalk to extract firmware contents."""
    try:
        subprocess.check_call(
            ["binwalk", "--extract", "--directory", extract_dir, firmware]
        )
    except subprocess.CalledProcessError as e:
        print(f"[!] binwalk extraction failed: {e}")
        sys.exit(1)

def find_rootfs_img(extracted_dir):
    """Locate rootfs.img / decompressed.bin inside binwalk extraction folder."""
    for root, dirs, files in os.walk(extracted_dir):
        for f in files:
            if f.lower() in ("rootfs.img", "decompressed.bin"):
                return os.path.join(root, f)
    return None

def extract_rootfs_cpio(raw_img):
    """Extract raw cpio rootfs.img into a temp folder."""
    rootfs_dir = tempfile.mkdtemp(prefix="rootfs_")
    try:
        print(f"[*] Extracting cpio {raw_img} → {rootfs_dir}")
        subprocess.run(
            ["cpio", "-idm"],
            cwd=rootfs_dir,
            input=open(raw_img, "rb").read(),
            check=True
        )
        return rootfs_dir
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to extract rootfs cpio: {e}")
        shutil.rmtree(rootfs_dir)
        return None

def find_gdbserver(rootfs_dir):
    """Search for gdbserver inside the extracted rootfs."""
    for root, dirs, files in os.walk(rootfs_dir):
        if "gdbserver" in files:
            full_path = os.path.join(root, "gdbserver")
            # Optional: ensure path contains usr/bin
            if "usr" in full_path and "bin" in full_path:
                return full_path
    return None

def main():
    parser = argparse.ArgumentParser(description="Check if Cisco ASA firmware contains gdbserver")
    parser.add_argument("-f", "--file", required=True, help="Path to ASA firmware .bin file")
    args = parser.parse_args()

    firmware = os.path.abspath(args.file)
    if not os.path.isfile(firmware):
        print(f"[!] File not found: {firmware}")
        sys.exit(1)

    tempdir = tempfile.mkdtemp(prefix="asa_fw_")
    rootfs_dir = None
    try:
        print(f"[*] Extracting firmware to {tempdir} ...")
        run_binwalk_extract(firmware, tempdir)

        rootfs_img = find_rootfs_img(tempdir)
        if not rootfs_img:
            print("\033[31m[-] rootfs.img / decompressed.bin not found\033[0m")  # red
            return

        rootfs_dir = extract_rootfs_cpio(rootfs_img)
        if not rootfs_dir:
            print("\033[31m[-] Failed to extract rootfs\033[0m")  # red
            return

        gdbserver_path = find_gdbserver(rootfs_dir)
        if gdbserver_path:
            fname = os.path.basename(firmware)
            print(f"\033[32m[+] gdbserver found at: {gdbserver_path}\033[0m")  # green
            # Also print the firmware filename on a single line for easy parsing
            print(f"[FOUND_FILE]{fname}")
            with open("results.txt", "a") as f:
                f.write(f"{fname}\n")
            sys.exit(2)
        else:
            print("\033[31m[-] gdbserver not found in rootfs/usr/bin\033[0m")  # red


    finally:
        if rootfs_dir and os.path.exists(rootfs_dir):
            shutil.rmtree(rootfs_dir)
        shutil.rmtree(tempdir)

if __name__ == "__main__":
    main()
