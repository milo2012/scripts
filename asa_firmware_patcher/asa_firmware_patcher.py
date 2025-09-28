#!/usr/bin/env python3
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

REQUIRED_CMDS = ["cpio", "gzip", "git", "python3"]

def run(cmd, cwd=None, input_bytes=None):
    msg = f"[*] Running: {' '.join(cmd)}"
    if cwd:
        msg += f" (cwd={cwd})"
    print(msg)
    subprocess.run(cmd, cwd=cwd, input=input_bytes, check=True)

def check_dependencies():
    missing = [cmd for cmd in REQUIRED_CMDS if shutil.which(cmd) is None]
    if missing:
        print("[!] Missing dependencies:", ", ".join(missing))
        sys.exit(1)
    if shutil.which("pip3") is None:
        print("[!] pip3 not found. Please install python3-pip and re-run.")
        sys.exit(1)
    try:
        import binwalk
    except ImportError:
        print("[!] Binwalk Python module not found")
        print("[!] Please install binwalk via pip3: pip3 install --user binwalk")
        sys.exit(1)

def patch_rcS(rcS_path):
    if not os.path.exists(rcS_path):
        print("[!] rcS not found at", rcS_path)
        sys.exit(1)

    with open(rcS_path, "r") as f:
        content = f.read()

    # 1) Uncomment lina_monitor
    commented_line = r'#echo "/asa/bin/lina_monitor'
    uncommented_line = r'echo "/asa/bin/lina_monitor'

    if commented_line in content:
        print("[*] Replacing ttyUSB0 with ttyS02 in rcS...")
        run(["sed", "-i.bak", r's/^#\(.*ttyUSB0.*\)/\1/; s/ttyUSB0/ttyS02/g', rcS_path])
    elif uncommented_line in content:
        print("[*] Debugger line already enabled, continuing...")
    else:
        print("[!] Debugger line not found in rcS. Please check manually.")
        sys.exit(1)

    # 2) Replace ttyUSB0 lines with 1ttyS02
    print("[*] Replacing ttyUSB0 with ttyS02 in rcS...")
    run(["sed", "-i.bak", r's/#\(.*ttyUSB0.*\)/1ttyS02/', rcS_path])


def main():
    parser = argparse.ArgumentParser(description="ASA Firmware Patch Tool")
    parser.add_argument("firmware", help="Path to ASA .bin firmware file")
    parser.add_argument("-o", "--output", help="Path for patched firmware output", default=None)
    parser.add_argument("--no-repack", action="store_true",
                        help="Do not repack rootfs; stop after patching rcS and exit")
    parser.add_argument("--rootfs-dir", help="Use a pre-edited rootfs folder instead of unpacking", default=None)
    args = parser.parse_args()

    check_dependencies()

    firmware = os.path.abspath(args.firmware)
    if not os.path.isfile(firmware):
        print("[!] Firmware file not found:", firmware)
        sys.exit(1)

    workdir = tempfile.mkdtemp(prefix="asa_patch_")
    print(f"[*] Working directory: {workdir}")

    try:
        # Working copies of firmware
        fw_orig = os.path.join(workdir, "asa.bin.orig")
        fw_copy = os.path.join(workdir, "asa.bin")
        shutil.copy(firmware, fw_orig)
        shutil.copy(firmware, fw_copy)

        # Determine rootfs folder
        if args.rootfs_dir:
            rootfs = os.path.abspath(args.rootfs_dir)
            if not os.path.isdir(rootfs):
                print("[!] Provided rootfs-dir does not exist:", rootfs)
                sys.exit(1)
            print(f"[*] Using manually edited rootfs: {rootfs}")

            # Patch rcS even if --rootfs-dir is used
            rcS = os.path.join(rootfs, "asa", "scripts", "rcS")
            patch_rcS(rcS)

            if args.no_repack:
                print("[*] --rootfs-dir with --no-repack; stopping before repack.")
                print(f"[*] Temporary folder left at: {workdir}")
                sys.exit(0)

        else:
            # Extract firmware
            run(["binwalk", "-e", fw_copy], cwd=workdir)

            # Locate extracted folder
            extracted = None
            for root, dirs, files in os.walk(workdir):
                for d in dirs:
                    if d.endswith(".bin.extracted"):
                        extracted = os.path.join(root, d)
            if not extracted:
                print("[!] Could not find extracted folder")
                sys.exit(1)

            # Find rootfs image
            decomp = None
            for root, dirs, files in os.walk(extracted):
                for f in files:
                    if f == "decompressed.bin" or f.lower() == "rootfs.img" or f.endswith(".img.gz"):
                        decomp = os.path.join(root, f)
                        break
            if not decomp:
                print("[!] Could not find rootfs image (decompressed.bin / rootfs.img)")
                sys.exit(1)

            # Decompress if gzipped
            if decomp.endswith(".gz"):
                import gzip
                decompressed_path = os.path.join(workdir, "rootfs.img")
                with gzip.open(decomp, "rb") as f_in, open(decompressed_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
                decomp = decompressed_path

            # Unpack rootfs
            rootfs = os.path.join(workdir, "rootfs")
            os.makedirs(rootfs, exist_ok=True)
            run(["cpio", "-idmv"], cwd=rootfs, input_bytes=open(decomp, "rb").read())

            # Patch rcS
            rcS = os.path.join(rootfs, "asa", "scripts", "rcS")
            patch_rcS(rcS)

            if args.no_repack:
                print("[*] --no-repack flag set. Stopping after patching rcS.")
                print(f"[*] Temporary folder left at: {workdir}")
                sys.exit(0)

        # Repack rootfs
        decomp_new = os.path.join(workdir, "decompressed_new.bin")
        rootfs_img = os.path.join(workdir, "rootfs.img.gz")
        run(["bash", "-c", f"cd {rootfs} && find . | cpio -o -H newc > {decomp_new}"])
        with open(decomp_new, "rb") as f_in, open(rootfs_img, "wb") as f_out:
            subprocess.run(["gzip", "-9", "-c"], stdin=f_in, stdout=f_out, check=True)

        # Clone asafw if needed
        asafw = os.path.join(workdir, "asafw")
        if not os.path.exists(asafw):
            run(["git", "clone", "https://github.com/nccgroup/asafw"], cwd=workdir)

        # Patch firmware using asafw
        run([sys.executable, "bin.py", "-r", "-f", fw_copy, "-g", rootfs_img], cwd=asafw)

        # Final output
        final_fw_path = os.path.abspath(args.output) if args.output else os.path.join(os.getcwd(), "asa_patched.bin")
        shutil.copy(fw_copy, final_fw_path)
        print("[✓] Patched firmware saved to:", final_fw_path)
        print("[*] Original firmware backup:", fw_orig)

    finally:
        # Cleanup
        if not args.no_repack and not args.rootfs_dir and os.path.exists(workdir):
            shutil.rmtree(workdir)
            print(f"[*] Cleaned up temporary working directory: {workdir}")
        else:
            print(f"[*] Temporary folder left at: {workdir}")

if __name__ == "__main__":
    main()
