# pentesting-scripts

This repository contains custom tools and templates developed for penetration testing, version detection, and reconnaissance across various services and platforms.

## 📁 nuclei-templates/

The `nuclei-templates/` folder includes a curated collection of [Nuclei](https://github.com/projectdiscovery/nuclei) templates that I created to assist with fingerprinting and version identification. These templates are especially useful during reconnaissance and vulnerability assessments, helping to quickly detect software versions and potential misconfigurations.

## 🌐 detect_netscaler_version.py

Detects Citrix NetScaler versions by downloading the EXE installer, extracting the MSI, and reading its ProductVersion.

## 📜 detect_esxi_version.py

This script retrieves version information from the official Broadcom Knowledge Base ([knowledge.broadcom.com](https://knowledge.broadcom.com)) and scans a target URL or list of URLs to identify the ESXi server’s release name, version, and build ID. This facilitates efficient mapping to known CPE (Common Platform Enumeration) entries for vulnerability assessment and inventory tracking.

## 🛠️ xss_payload_numbering.py

The `xss_payload_numbering.py` script replaces `alert()` and `prompt()` calls in XSS payloads with uniquely numbered versions. This helps you track which payload triggered a vulnerability when using Burp Intruder, ffuf, or other fuzzing tools.

For example, you can use it to process payloads from:

> https://github.com/payloadbox/xss-payload-list/blob/master/Intruder/xss-payload-list.txt

Each modified payload will be tagged with a unique identifier, allowing precise identification during testing.

### 📡 telnet_scanner.py

A lightweight Telnet detection tool. Provide it with a list of targets in `IP:port` format, and it will attempt to detect Telnet or Telnet-like services that may be missed by traditional scanners like Nmap. Useful for finding non-standard ports or obfuscated Telnet services.
    
## 🕵️‍♂️ capture_cdp_eigrp.py

A Python script that captures and prints Cisco Discovery Protocol (CDP) and Enhanced Interior Gateway Routing Protocol (EIGRP) packets from the network. Useful for passive network reconnaissance and gathering layer 2 and layer 3 routing information during penetration tests.

- **Dependencies:** Requires Python `scapy` library.
- **Usage:** Run the script with appropriate privileges on a Linux machine connected to the target network segment.
- **Output:** Prints details of observed CDP and EIGRP packets in real time, aiding in network topology discovery and device fingerprinting.

## 🔍 check_svn_cleartext_auth.py

Checks if an SVN host supports cleartext SASL authentication mechanisms such as PLAIN or LOGIN.

---

Additional scripts and modules will be added over time to support a wider range of enumeration and exploitation tasks.

