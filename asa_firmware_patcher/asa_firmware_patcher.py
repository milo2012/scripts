#!/usr/bin/env python3
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

REQUIRED_CMDS = ["cpio", "gzip", "git", "python3"]

def run(cmd, cwd=None, input_bytes=None):
    """Run a shell command with optional cwd and input."""
    msg = f"[*] Running: {' '.join(cmd)}"
    if cwd:
        msg += f" (cwd={cwd})"
    print(msg)
    subprocess.run(cmd, cwd=cwd, input=input_bytes, check=True)

def check_dependencies():
    """Check required commands and binwalk, prompt user if missing."""
    missing = [cmd for cmd in REQUIRED_CMDS if shutil.which(cmd) is None]
    if missing:
        print("[!] Missing dependencies:", ", ".join(missing))
        print("[!] Please install them manually and re-run.")
        sys.exit(1)
    else:
        print("[*] All dependencies present.")

    if shutil.which("pip3") is None:
        print("[!] pip3 not found. Please install python3-pip and re-run.")
        sys.exit(1)

    try:
        import binwalk
    except ImportError:
        print("[!] Binwalk Python module not found")
        print("[!] Please install binwalk via pip3: pip3 install --user binwalk")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="ASA Firmware Patch Tool")
    parser.add_argument("firmware", help="Path to ASA .bin firmware file")
    parser.add_argument("-o", "--output", help="Path for patched firmware output", default=None)
    args = parser.parse_args()

    check_dependencies()

    firmware = os.path.abspath(args.firmware)
    if not os.path.isfile(firmware):
        print("[!] Firmware file not found:", firmware)
        sys.exit(1)

    workdir = tempfile.mkdtemp(prefix="asa_patch_")
    print(f"[*] Working directory: {workdir}")

    try:
        # Prepare working copies
        fw_orig = os.path.join(workdir, "asa.bin.orig")
        fw_copy = os.path.join(workdir, "asa.bin")
        shutil.copy(firmware, fw_orig)
        shutil.copy(firmware, fw_copy)

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
        if not os.path.exists(rcS):
            print("[!] rcS not found at", rcS)
            sys.exit(1)

        with open(rcS, "r") as f:
            content = f.read()

        commented_line = r'#echo "/asa/bin/lina_monitor'
        uncommented_line = r'echo "/asa/bin/lina_monitor'

        if commented_line in content:
            print("[*] Uncommenting debugger line in rcS...")
            run(["sed", "-i.bak", r's/^#\(echo "\/asa\/bin\/lina_monitor.*\)/\1/', rcS])
        elif uncommented_line in content:
            print("[*] Debugger line already enabled, continuing...")
        else:
            print("[!] Debugger line not found in rcS. Please check manually.")
            sys.exit(1)

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

        # Determine final output path
        if args.output:
            final_fw_path = os.path.abspath(args.output)
        else:
            final_fw_path = os.path.join(os.getcwd(), "asa_patched.bin")  # default

        shutil.copy(fw_copy, final_fw_path)
        print("[✓] Patched firmware saved to:", final_fw_path)
        print("[*] Original firmware backup:", fw_orig)

    finally:
        # Safe cleanup of temp folder
        if os.path.exists(workdir):
            shutil.rmtree(workdir)
            print(f"[*] Cleaned up temporary working directory: {workdir}")

if __name__ == "__main__":
    main()
