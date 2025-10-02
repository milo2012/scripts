#!/usr/bin/env python3
import argparse
import os
import subprocess
import fnmatch
import shutil
import tempfile

def run(cmd):
    print("[+] " + " ".join(cmd))
    subprocess.run(cmd, check=True)

def extract_asa_bin(qcow2_file, output_dir):
    # Ensure nbd module loaded
    run(["sudo", "modprobe", "nbd", "max_part=8"])

    nbd = "/dev/nbd0"  # always use first
    part = nbd + "p1"  # first partition

    # Connect QCOW2
    run(["sudo", "qemu-nbd", "--connect", nbd, qcow2_file])

    # Temporary mount point
    tmpmnt = tempfile.mkdtemp(prefix="qcowmnt_")
    try:
        # Mount the first partition read-only
        run(["sudo", "mount", "-o", "ro", part, tmpmnt])

        # Walk files and copy asa*.bin
        copied = False
        for root, dirs, files in os.walk(tmpmnt):
            for f in files:
                if fnmatch.fnmatch(f, "asa*.bin"):
                    src = os.path.join(root, f)
                    dest = os.path.join(output_dir, f)
                    print(f"[+] Copying {src} → {dest}")
                    shutil.copy2(src, dest)
                    copied = True

        if not copied:
            print("[!] No asa*.bin found.")
        else:
            print("[+] Done extracting.")
        run(["sudo", "umount", tmpmnt])
    finally:
        run(["sudo", "qemu-nbd", "--disconnect", nbd])
        os.rmdir(tmpmnt)

def main():
    parser = argparse.ArgumentParser(description="Extract Cisco ASA asa*.bin from QCOW2")
    parser.add_argument("-f", "--file", required=True, help="Path to QCOW2 file")
    parser.add_argument("-o", "--output", default=".", help="Output directory")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[!] QCOW2 file not found: {args.file}")
        return
    if not os.path.isdir(args.output):
        os.makedirs(args.output)

    extract_asa_bin(args.file, args.output)

if __name__ == "__main__":
    main()
