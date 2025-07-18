#!/usr/bin/env python3
import os
import subprocess
import re
import json
import time
import argparse
from time import sleep
import urllib.request
import csv
from ipaddress import ip_network


# === Colors ===
ANSI_RED = "\033[91m"
ANSI_GREEN = "\033[92m"
ANSI_UNDERLINE = "\033[4m"
ANSI_RESET = "\033[0m"

# === CLI Arguments ===
parser = argparse.ArgumentParser(description="Check for unintended transit advertisement.")
group = parser.add_mutually_exclusive_group(required=True)
parser.add_argument("-a", "--target-asn", type=int, required=True, help="Your ASN (used to match transit routes)")
group.add_argument("-s", "--as-set", help="IRR AS-SET to enumerate prefixes from")
group.add_argument("-f", "--prefix-file", help="File containing prefixes to analyze")
parser.add_argument("-m", "--missing", help="Comma-separated list of expected upstream ASNs.")
parser.add_argument("-p", "--parallel", type=int, default=4, help="Number of parallel prefix queries (0 = sequential, 4 = default)")
parser.add_argument("--no-cache", action="store_true", help="Force re-query even if recent data is cached")
parser.add_argument("--debug", action="store_true", help="Enable debug output")
args = parser.parse_args()

# === Configuration ===
DATESTAMP = time.strftime("%Y%m%d-%H%M%S")
ASN = str(args.target_asn)
OUTPUT_DIR = os.path.expanduser("~/.workdir-irr-toolbox")
os.makedirs(OUTPUT_DIR, exist_ok=True)
PREFIX_FILE = args.prefix_file or f"{OUTPUT_DIR}/prefixes.txt"
OUTPUT_JSON = f"{OUTPUT_DIR}/bgp-tools.json"
IGNORE_FILE = os.path.expanduser("~/.checkbgp_prefixignore")
CACHE_TTL = 3600
USER_AGENT_FILE = os.path.expanduser("~/.bgp-tools-useragent")

def garbage_collect_tmux(debug=False):
    """Kill stale tmux sessions created by this script only (prefixed with 'bgp_')"""
    try:
        result = subprocess.run(["tmux", "ls"], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            if debug:
                print("+DEBUG: No tmux server running or no sessions to list")
            return

        sessions = result.stdout.strip().splitlines()
        for line in sessions:
            match = re.match(r'^(bgp_[^\s:]+)', line)
            if match:
                session = match.group(1)
                # Optional: Check age by pid file or timestamp if needed
                if debug:
                    print(f"+DEBUG: Killing stale tmux session: {session}")
                subprocess.run(["tmux", "kill-session", "-t", session], check=False)
    except Exception as e:
        if debug:
            print(f"+DEBUG: Error during tmux garbage collection: {e}")

def debug(msg):
    if args.debug:
        print(f"+DEBUG: {msg}")

def get_user_agent():
    try:
        with open(USER_AGENT_FILE, "r") as f:
            agent = f.read().strip()
            if agent:
                return agent
    except Exception as e:
        if args.debug:
            print(f"+DEBUG: Failed to load User-Agent from {USER_AGENT_FILE}: {e}")
    # Fallback
    return "Python bgp.tools fetcher (no UA file found)"

ASN_CSV_PATH = os.path.join(OUTPUT_DIR, "asns.csv")
ASN_CSV_TTL = 86400  # 24 hours
ASN_MAP = {}

def load_asn_names():
    now = time.time()
    exists = os.path.exists(ASN_CSV_PATH)
    age = now - os.path.getmtime(ASN_CSV_PATH) if exists else None

    if args.debug:
        if exists:
            print(f"+DEBUG: ASN CSV exists at {ASN_CSV_PATH}")
            print(f"+DEBUG: ASN CSV age: {int(age)} seconds (TTL: {ASN_CSV_TTL})")
        else:
            print(f"+DEBUG: ASN CSV does not exist")

    needs_download = not exists or age > ASN_CSV_TTL

    if needs_download:
        try:
            print(f"+DEBUG: Downloading fresh ASN CSV to {ASN_CSV_PATH}")
            #urllib.request.urlretrieve("https://bgp.tools/asns.csv", ASN_CSV_PATH)
            user_agent = get_user_agent()
            debug(f"Using User-Agent: {user_agent}")
            req = urllib.request.Request(
                "https://bgp.tools/asns.csv",
                headers={"User-Agent": user_agent}
            )
            with urllib.request.urlopen(req) as response, open(ASN_CSV_PATH, 'wb') as out_file:
                out_file.write(response.read())

        except Exception as e:
            print(f"+DEBUG: Failed to download ASN names: {e}")
            return

    try:
        with open(ASN_CSV_PATH, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    asn_field = row.get("asn", "").strip()
                    name_field = row.get("name", "").strip()
                    if asn_field.startswith("AS"):
                        asn = int(asn_field[2:])
                    else:
                        asn = int(asn_field)
                    name = name_field.split()[0] if name_field else ""
                    ASN_MAP[asn] = name
                except Exception as e:
                    if args.debug:
                        print(f"+DEBUG: Error parsing row: {row} -> {e}")
        if args.debug:
            print(f"+DEBUG: Loaded {len(ASN_MAP)} ASN names")
    except Exception as e:
        print(f"+DEBUG: Failed to read ASN CSV: {e}")

EXPECTED_UPSTREAMS = []
if args.missing:
    EXPECTED_UPSTREAMS = sorted(set(int(x.strip()) for x in args.missing.split(",") if x.strip().isdigit()))
    load_asn_names()  # populate ASN_MAP

# === Prefix Acquisition ===
if args.prefix_file:
    if not os.path.exists(PREFIX_FILE):
        print(f"ERROR: Prefix file not found: {PREFIX_FILE}")
        exit(1)
else:
    debug(f"Enumerating prefixes from AS-SET: {args.as_set}")
    result = subprocess.run(
        ["./enumerate_as-set_prefixes", "-q", args.as_set],
        stdout=open(PREFIX_FILE, "w"),
        stderr=subprocess.PIPE,
        text=True
    )
    if result.returncode != 0:
        print(f"ERROR: Failed to enumerate prefixes from AS-SET: {args.as_set}")
        print(result.stderr)
        exit(1)

with open(PREFIX_FILE, "r") as f:
    all_prefixes = [line.strip() for line in f if line.strip()]

if not all_prefixes:
    print("ERROR: Prefix list is empty.")
    exit(1)

# === Ignore File ===
ignored_prefixes = set()
if os.path.exists(IGNORE_FILE):
    with open(IGNORE_FILE, "r") as f:
        ignored_prefixes = set(line.strip() for line in f if line.strip())
    debug(f"Found ignore file: {IGNORE_FILE}")
    debug(f"Ignoring {len(ignored_prefixes)} prefix(es): {sorted(ignored_prefixes)}")
else:
    debug(f"No ignore file found at: {IGNORE_FILE}")

queried_prefixes = []
for prefix in all_prefixes:
    if prefix in ignored_prefixes:
        debug(f"Skipping {prefix} - listed in ignore file")
    else:
        queried_prefixes.append(prefix)

# === BGP Query Logic ===
def query_prefix(prefix, force=False):
    sanitized = prefix.replace(".", "_").replace("/", "_")
    session = f"bgp_{sanitized}"
    output_file = f"{OUTPUT_DIR}/bgp-tools-{sanitized}.txt"

    if os.path.exists(output_file):
        age = time.time() - os.path.getmtime(output_file)
        if force:
            debug(f"Forcing re-query of {prefix} - ignoring cache")
        elif not args.no_cache and age < CACHE_TTL:
            debug(f"Skipping {prefix} - cached file is fresh ({int(age)}s old)")
            return
        else:
            debug(f"Refreshing {prefix} - cached file is stale ({int(age)}s old)")
    else:
        debug(f"Querying {prefix} - no cached file found")

    subprocess.run(
        f'tmux new-session -d -s {session} "ssh -tt lg@bgp.tools"',
        shell=True,
        check=True
    )

    sleep(4)
    cmd = f"show route {prefix} short match {ASN}"
    subprocess.run(f'tmux send-keys -t {session} "{cmd}" C-m', shell=True, check=True)
    sleep(6)

    subprocess.run(f"tmux capture-pane -t {session}:0 -pJS -99999 > {output_file}", shell=True, check=True)
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

# === Perform Queries ===
#for prefix in queried_prefixes:
#    query_prefix(prefix)
if args.parallel == 0:
    if args.debug:
        print(f"+DEBUG: Running prefix queries sequentially")
    for prefix in queried_prefixes:
        query_prefix(prefix)
else:
    if args.debug:
        print(f"+DEBUG: Running prefix queries with {args.parallel} parallel threads")
    from concurrent.futures import ThreadPoolExecutor, as_completed

    with ThreadPoolExecutor(max_workers=args.parallel) as executor:
        futures = {executor.submit(query_prefix, prefix): prefix for prefix in queried_prefixes}
        for future in as_completed(futures):
            prefix = futures[future]
            try:
                future.result()
            except Exception as e:
                print(f"[!] Error querying {prefix}: {e}")


debug("All queries complete. Beginning JSON conversion...")

# === Parse Query Results ===
line_pattern = re.compile(r'^\[\{AS(\d+)[^}]*\} [^\]]*\] \[([^\]]+)\] \{\[([^\]]*)\]\}')
file_pattern = re.compile(r'bgp-tools-(.+)\.txt')

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
        f"{OUTPUT_DIR}/bgp-tools-{prefix.replace('.', '_').replace('/', '_')}.txt"
        for prefix in queried_prefixes
    }

    for path in expected_txt_files:
        prefix = extract_prefix(path)
        if not prefix or not os.path.exists(path):
            continue

        try:
            with open(path, "r") as f:
                buffer = ""
                for line in f:
                    buffer += line.strip() + " "
                    if buffer.strip().endswith("]}"):
                        match = line_pattern.match(buffer.strip())
                        if match:
                            try:
                                source_asn = int(match.group(1))
                                as_path = [int(asn) for asn in match.group(2).split()]
                                communities = match.group(3).split()
                                combined.setdefault(prefix, []).append({
                                    "source_asn": source_asn,
                                    "as_path": as_path,
                                    "communities": communities
                                })
                            except Exception as inner_e:
                                if args.debug:
                                    print(f"+DEBUG: Error parsing values in {path}: {inner_e}")
                        buffer = ""
        except Exception as outer_e:
            if args.debug:
                print(f"+DEBUG: Failed reading {path}: {outer_e}")
            continue

    return combined

combined_data = parse_all_files()
with open(OUTPUT_JSON, "w") as f:
    json.dump(combined_data, f, indent=2)

# === Retry Missing Prefixes ===
actual_prefixes = set(combined_data.keys())
expected_prefixes = set(queried_prefixes)
missing_prefixes = sorted(expected_prefixes - actual_prefixes)

if missing_prefixes:
    debug(f"{len(missing_prefixes)} prefix(es) missing from JSON, retrying:")
    for p in missing_prefixes:
        debug(f"  - {p}")
    for p in missing_prefixes:
        query_prefix(p, force=True)
    debug("Retrying complete. Re-parsing all files...")
    combined_data = parse_all_files()
    with open(OUTPUT_JSON, "w") as f:
        json.dump(combined_data, f, indent=2)

# === Summary ===
if args.debug:
    print("\n+DEBUG: ===== Summary =====")
    print(f"+DEBUG: Total prefixes in input list    : {len(all_prefixes)}")
    print(f"+DEBUG: Ignored via prefix ignore file  : {len(ignored_prefixes)}")
    print(f"+DEBUG: Prefixes queried                : {len(queried_prefixes)}")
    print(f"+DEBUG: Prefixes in final JSON output   : {len(combined_data)}")

    still_missing = sorted(set(queried_prefixes) - set(combined_data.keys()))
    if still_missing:
        print(f"+DEBUG: Still missing {len(still_missing)} prefix(es) after retry:")
        for p in still_missing:
            print(f"    - {p}")
    else:
        print("+DEBUG: All previously missing prefixes successfully recovered.")
    print(f"+DEBUG: JSON written to: {OUTPUT_JSON}")

load_asn_names()

if EXPECTED_UPSTREAMS:
    header = f"{'Prefix':<20} {'Expected Upstream':<32} Status"
else:
    upstream_header = f"Observed Upstreams from AS{args.target_asn}"
    header = f"{'Prefix':<20}{upstream_header}"

print(header)
print("-" * len(header))

for prefix, entries in sorted(combined_data.items(), key=lambda x: ip_network(x[0])):
    if EXPECTED_UPSTREAMS:
        for i, expected_asn in enumerate(EXPECTED_UPSTREAMS):
            name = ASN_MAP.get(expected_asn, "???")
            tag_text = f"{expected_asn} ({name})"
            appearance_count = sum(1 for entry in entries if expected_asn in entry.get("as_path", []))
            was_seen = appearance_count > 6

            # Colors
            color = ANSI_GREEN if was_seen else ANSI_RED
            tag = f"{color}{tag_text:<32}{ANSI_RESET}"
            status_text = "[ OK ]" if was_seen else "[FAIL]"
            status_col = f"{color}{status_text.center(11)}{ANSI_RESET}"

            # Prefix printed only on first line
            #prefix_col = f"{prefix:<20}" if i == 0 else " " * 20
            if i == 0:
                prefix_col = f"{ANSI_UNDERLINE}{prefix}{ANSI_RESET}{' ' * (20 - len(prefix))}"
            else:
                prefix_col = " " * 20
            print(f"{prefix_col} {tag} {status_col}")
        
        print()  # blank line between prefixes
        continue  # skip regular output

    upstreams_by_path = {}  # key: tuple(as_path), value: upstream ASN (before target)
    for entry in entries:
        path = entry.get("as_path", [])
        if args.target_asn not in path or path.index(args.target_asn) == 0:
            continue
        cleaned_path = []
        [cleaned_path.append(asn) for asn in path if asn not in cleaned_path]  # dedup in-place
        idx = cleaned_path.index(args.target_asn)
        upstream = cleaned_path[idx - 1]
        upstreams_by_path[tuple(cleaned_path)] = upstream

    # Count frequency of each upstream ASN across unique as_paths
    freq = {}
    for upstream in upstreams_by_path.values():
        freq[upstream] = freq.get(upstream, 0) + 1

    significant_upstreams = sorted(asn for asn, count in freq.items() if count > 1)
    if not significant_upstreams:
        continue

    #print(f"{prefix:<20}{significant_upstreams[0]} ({ASN_MAP.get(significant_upstreams[0], '')})")
    underlined_prefix = f"{ANSI_UNDERLINE}{prefix}{ANSI_RESET}{' ' * (20 - len(prefix))}"
    print(f"{underlined_prefix}{significant_upstreams[0]} ({ASN_MAP.get(significant_upstreams[0], '')})")

    for asn in significant_upstreams[1:]:
        print(f"{'':<20}{asn} ({ASN_MAP.get(asn, '')})")
    print()  # spacing between prefixes

