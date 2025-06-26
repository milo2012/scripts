#!/usr/bin/env python3
"""
XSS Payload Numbering Script for Burp Suite Intruder/Fuzzing

Author: milo2012

Description:
------------
When testing for reflected/stored XSS using tools like Burp Suite Intruder, it's common to use payloads that trigger 
JavaScript functions like `alert(1)` or `prompt(1)`. However, if all payloads use the same numeric value (e.g., 1), 
it becomes difficult to correlate which exact payload triggered a response, especially when testing large payload lists.

This script processes an input file containing XSS payloads and replaces instances of `alert(...)` or `prompt(...)` 
with a uniquely numbered version like `alert(42)` or `prompt(42)`, incrementing the number for each line. 
This helps testers quickly identify which payload succeeded based on the number returned in the reflected response 
(e.g., seeing `alert(42)` in the browser or response body helps you trace back to the exact payload).

Typical use case:
-----------------
Given an input file such as:
    '>alert(1)</script><script/1='
    '*/prompt(1)</script><script>/*'

This script will convert it to:
    '>alert(1)</script><script/1='
    '*/prompt(2)</script><script>/*'

Usage:
------
python3 modify_xss_payloads.py -f input_payloads.txt -o output_payloads_numbered.txt
"""

import argparse
import re

def generate_numeric_payloads(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as infile:
        lines = infile.readlines()

    count = 1
    modified_lines = []

    for line in lines:
        original = line.strip()

        # Only process lines containing alert( or prompt(
        if re.search(r'\b(alert|prompt)\s*\(', original, re.IGNORECASE):
            # Replace alert(...) or prompt(...) with alert(count) or prompt(count)
            modified = re.sub(
                r'\b(alert|prompt)\s*\(\s*([^\)]*?)\s*\)',
                lambda m: f"{m.group(1).lower()}({count})",
                original,
                flags=re.IGNORECASE
            )

            if modified.strip():
                modified_lines.append(modified)
                count += 1

    with open(output_file, 'w', encoding='utf-8') as outfile:
        outfile.write('\n'.join(modified_lines) + '\n')

    print(f"Generated {count - 1} payloads in {output_file}.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Replace alert()/prompt() with numeric IDs for Burp testing.")
    parser.add_argument("-f", "--file", required=True, help="Input file with XSS payloads")
    parser.add_argument("-o", "--output", required=True, help="Output file for numeric payloads")

    args = parser.parse_args()
    generate_numeric_payloads(args.file, args.output)
