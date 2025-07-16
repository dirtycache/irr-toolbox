#!/usr/bin/env python3
import os
import subprocess
import glob
import re
import json
import time
import argparse
from time import sleep

# Configuration
ASN = "19366"
DATESTAMP = "20250716-022440"  # Adjust manually
PREFIX_FILE = f"./.workdir/prefixes-{DATESTAMP}.txt"
OUTPUT_DIR = "./.workdir"
OUTPUT_JSON = f"{OUTPUT_DIR}/bgp-tools-{DATESTAMP}.json"
IGNORE_FILE = os.path.expanduser("~/.checkbgp_prefixignore")
CACHE_TTL = 3600

# CLI args
parser = argparse.ArgumentParser(description="Run BGP queries and build JSON from output.")
parser.add_argument("--no-cache", action="store_true", help="Force re-query even if recent data is cached")
args = parser.parse_args()

# Load ignore list
ignored_prefixes = set()
if os.path.exists(IGNORE_FILE):
    with open(IGNORE_FILE, "r") as f:
        ignored_prefixes = set(line.strip() for line in f if line.strip())
    print(f"[+] Found ignore file: {IGNORE_FILE}")
    print(f"[+] Ignoring {len(ignored_prefixes)} prefix(es): {sorted(ignored_prefixes)}")
else:
    print(f"[+] No ignore file found at: {IGNORE_FILE}")

# Read prefix list
if not os.path.exists(PREFIX_FILE):
    print(f"ERROR: Prefix file not found: {PREFIX_FILE}")
    exit(1)

with open(PREFIX_FILE, "r") as f:
    all_prefixes = [line.strip() for line in f if line.strip()]

if not all_prefixes:
    print("ERROR: Prefix file is empty")
    exit(1)

# Final working set
queried_prefixes = []
for prefix in all_prefixes:
    if prefix in ignored_prefixes:
        print(f"[+] Skipping {prefix} - listed in ignore file")
    else:
        queried_prefixes.append(prefix)

def query_prefix(prefix, force=False):
    sanitized = prefix.replace(".", "_").replace("/", "_")
    session = f"bgp_{sanitized}"
    output_file = f"{OUTPUT_DIR}/bgp-tools-{sanitized}-{DATESTAMP}.txt"

    if os.path.exists(output_file):
        age = time.time() - os.path.getmtime(output_file)
        if force:
            print(f"[+] Forcing re-query of {prefix} - ignoring cache")
        elif not args.no_cache and age < CACHE_TTL:
            print(f"[+] Skipping {prefix} - cached file is fresh ({int(age)}s old)")
            return
        else:
            print(f"[+] Refreshing {prefix} - cached file is stale ({int(age)}s old)")
    else:
        print(f"[+] Querying {prefix} - no cached file found")

    subprocess.run(
        f'tmux new-session -d -s {session} "ssh -tt lg@bgp.tools"',
        shell=True,
        check=True
    )

    sleep(4)
    cmd = f"show route {prefix} short match {ASN}"
    subprocess.run(f'tmux send-keys -t {session} "{cmd}" C-m', shell=True, check=True)
    sleep(6)

    subprocess.run(f"tmux capture-pane -t {session}:0 -p -S -99999 > {output_file}", shell=True, check=True)
    subprocess.run(f"tmux send-keys -t {session} C-d", shell=True, check=True)

    for _ in range(30):
        result = subprocess.run(
            f"tmux has-session -t {session}",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if result.returncode != 0:
            break
        sleep(0.5)
    else:
        subprocess.run(f"tmux kill-session -t {session}", shell=True)

# Query all non-ignored prefixes
for prefix in queried_prefixes:
    query_prefix(prefix)

print("[+] All queries complete. Beginning JSON conversion...")

# Parsing regex
line_pattern = re.compile(r'^\[\{AS(\d+)[^\}]*\} [^\]]*\] \[([^\]]+)\] \{\[([^\]]*)\]\}')
file_pattern = re.compile(r'bgp-tools-(.+)-' + re.escape(DATESTAMP) + r'\.txt')

def extract_prefix(filename):
    basename = os.path.basename(filename)
    m = file_pattern.match(basename)
    if not m:
        return None
    parts = m.group(1).split("_")
    if len(parts) != 5:
        return None
    return ".".join(parts[:4]) + "/" + parts[4]

def parse_all_files():
    combined = {}
    expected_txt_files = {
        f"{OUTPUT_DIR}/bgp-tools-{prefix.replace('.', '_').replace('/', '_')}-{DATESTAMP}.txt"
        for prefix in queried_prefixes
    }

    for path in expected_txt_files:
        prefix = extract_prefix(path)
        if not prefix or not os.path.exists(path):
            continue
        with open(path, "r") as f:
            buffer = ""
            for line in f:
                buffer += line
                if buffer.strip().endswith("]}"):
                    match = line_pattern.match(buffer.strip())
                    if match:
                        source_asn = int(match.group(1))
                        as_path = [int(asn) for asn in match.group(2).split()]
                        communities = match.group(3).split()
                        combined.setdefault(prefix, []).append({
                            "source_asn": source_asn,
                            "as_path": as_path,
                            "communities": communities
                        })
                    buffer = ""
    return combined

# First pass parse and write JSON
combined_data = parse_all_files()
with open(OUTPUT_JSON, "w") as f:
    json.dump(combined_data, f, indent=2)

# Identify missing prefixes
actual_prefixes = set(combined_data.keys())
expected_prefixes = set(queried_prefixes)
missing_prefixes = sorted(expected_prefixes - actual_prefixes)

if missing_prefixes:
    print(f"[!] {len(missing_prefixes)} prefix(es) missing from JSON, retrying:")
    for p in missing_prefixes:
        print(f"    - {p}")
    for p in missing_prefixes:
        query_prefix(p, force=True)
    print("[+] Retrying complete. Re-parsing all files...")
    combined_data = parse_all_files()
    with open(OUTPUT_JSON, "w") as f:
        json.dump(combined_data, f, indent=2)

# Final summary
print("\n===== Summary =====")
print(f"Total prefixes in input list    : {len(all_prefixes)}")
print(f"Ignored via prefix ignore file  : {len(ignored_prefixes)}")
print(f"Prefixes queried                : {len(queried_prefixes)}")
print(f"Prefixes in final JSON output   : {len(combined_data)}")

still_missing = sorted(set(queried_prefixes) - set(combined_data.keys()))
if missing_prefixes:
    if still_missing:
        print(f"[!] Still missing {len(still_missing)} prefix(es) after retry:")
        for p in still_missing:
            print(f"    - {p}")
    else:
        print("[+] All previously missing prefixes successfully recovered.")

print(f"[+] JSON written to: {OUTPUT_JSON}")
