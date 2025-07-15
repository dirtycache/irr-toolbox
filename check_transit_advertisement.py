#!/usr/bin/env python3

import argparse
import json
import os
import sys
import subprocess
from datetime import datetime
import re
import socket

ANSI_RED = "\033[91m"
ANSI_GREEN = "\033[92m"
ANSI_RESET = "\033[0m"

def debug_print(debug, message):
    if debug:
        print(f"+DEBUG: {message}")

def run_bgp_batch(prefixes, target_asn, timestamp, debug=False):
    log_file = f".workdir/bgp-tools-batch-out-{timestamp}"
    cmds = '\n'.join([f"show route {p} short match {target_asn}" for p in prefixes])
    exp_script = "./bgp-batch.exp"
    if not os.path.exists(exp_script):
        print(f"FATAL: Expect script not found at {exp_script}")
        sys.exit(1)
    debug_print(debug, f"Calling {exp_script} with {len(prefixes)} commands, log_file: {log_file}")
    env = os.environ.copy()
    env["BGP_CMDS"] = cmds
    env["BGP_LOG"] = log_file
    subprocess.run(["expect", exp_script], env=env)
    print(f"Output written to: {log_file}")

def query_as_names(asns, debug=False):
    debug_print(debug, f"Querying AS names for: {asns}")
    try:
        s = socket.create_connection(("bgp.tools", 43), timeout=10)
        s.sendall(b"begin\n")
        for asn in asns:
            s.sendall(f"as{asn}\n".encode())
        s.sendall(b"end\n")
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
        s.close()
        result = {}
        for line in response.decode().splitlines():
            parts = line.split("|")
            if len(parts) >= 6:
                asn = parts[0].strip()
                name = parts[-1].strip()
                if asn.isdigit():
                    result[int(asn)] = name.split(",")[0].split(" ")[0]
        debug_print(debug, f"Resolved AS names: {result}")
        return result
    except Exception as e:
        print(f"Error resolving AS names: {e}")
        return {}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--target-asn", required=True, help="The ASN of which you want to check global propagation")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Text file of prefixes, one per line")
    group.add_argument("-s", "--as-set", help="IRR as-set object to enumerate prefixes")
    parser.add_argument("-p", "--include-single-source-paths", action="store_true", help="Include paths seen by only one source ASN")
    parser.add_argument("-m", "--missing", help="Comma-separated list of ASNs to verify propagation")
    parser.add_argument("-j", "--json", help="JSON input file (default .workdir/bgp-tools.json)", default=".workdir/bgp-tools.json")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    prefix_file = ".workdir/prefixes.txt"
    if args.file:
        prefix_file = args.file
        debug_print(args.debug, f"Using user-specified prefix file: {prefix_file}")
    elif args.as_set:
        os.makedirs(".workdir", exist_ok=True)
        debug_print(args.debug, f"Calling ./enumerate_as-set_prefixes -q {args.as_set} > {prefix_file}")
        subprocess.run(["./enumerate_as-set_prefixes", "-q", args.as_set], stdout=open(prefix_file, "w"), check=True)

    if not os.path.isfile(prefix_file) or os.path.getsize(prefix_file) == 0:
        print("FATAL: No prefixes to query!")
        sys.exit(1)

    with open(prefix_file) as f:
        prefixes = [line.strip() for line in f if line.strip()]
    debug_print(args.debug, f"Loaded {len(prefixes)} prefixes from {prefix_file}")

    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    debug_print(args.debug, f"Using UTC timestamp {timestamp}")
    run_bgp_batch(prefixes, args.target_asn, timestamp, debug=args.debug)

    if not os.path.exists(args.json):
        print(f"FATAL: Missing JSON file: {args.json}")
        sys.exit(1)

    with open(args.json) as f:
        data = json.load(f)

    as_name_map = {}
    check_asns = []
    if args.missing:
        check_asns = sorted(set(int(asn) for asn in args.missing.split(",")))
        as_name_map = query_as_names(check_asns, debug=args.debug)

    print()
    print(f"{'Prefix':<22} {'OriginAS':<8} Global Propagation from AS{args.target_asn}")

    for prefix in prefixes:
        entries = data.get(prefix, [])
        origin_asns = set()
        upstreams_seen = {}
        for entry in entries:
            path = entry.get("as_path", [])
            if args.target_asn in path:
                try:
                    idx = path.index(args.target_asn)
                    origin = path[-1]
                    origin_asns.add(origin)
                    for asn in path[idx + 1:]:
                        upstreams_seen.setdefault(asn, set()).add(entry["source_asn"])
                except ValueError:
                    continue

        if not upstreams_seen and not check_asns:
            print(f"{prefix:<22} {'':<8} (no as-paths including {args.target_asn})")
            continue

        origin_str = ",".join(str(asn) for asn in origin_asns) if origin_asns else ""
        print(f"{prefix:<22} {origin_str:<8}")

        if check_asns:
            for asn in check_asns:
                name = as_name_map.get(asn, "???")
                label = f"{ANSI_GREEN}[ OK ]{ANSI_RESET}" if asn in upstreams_seen else f"{ANSI_RED}[FAIL]{ANSI_RESET}"
                print(f"{'':<31} {asn:<8} {name:<30} {label}")
        else:
            line = []
            for asn, sources in sorted(upstreams_seen.items()):
                tag = "" if len(sources) > 1 or args.include_single_source_paths else "*"
                if tag == "*" and not args.include_single_source_paths:
                    continue
                color = ANSI_RED if tag == "*" else ""
                line.append(f"{color}{asn}{tag}{ANSI_RESET}")
            if line:
                print(f"{'':<31} {', '.join(line)}")

        print()

if __name__ == "__main__":
    main()
