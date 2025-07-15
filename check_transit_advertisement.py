#!/usr/bin/env python3

import json
import argparse
import socket

TARGET_ASN = "19366"

ANSI_RED = "\033[91m"
ANSI_GREEN = "\033[92m"
ANSI_RESET = "\033[0m"

def resolve_as_names(asn_list):
    """Resolve ASNs to names using whois bulkmode at bgp.tools"""
    query = "begin\n" + "\n".join(f"as{asn}" for asn in asn_list) + "\nend\n"
    asn_names = {}
    try:
        with socket.create_connection(("bgp.tools", 43), timeout=5) as sock:
            sock.sendall(query.encode())
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            lines = response.decode(errors="ignore").splitlines()
            for line in lines:
                parts = line.split("|")
                if len(parts) >= 6:
                    asn = parts[0].strip()
                    name = parts[-1].strip()
                    if asn.isdigit():
                        asn_names[asn] = name
    except Exception as e:
        print(f"{ANSI_RED}Warning: ASN name resolution failed: {e}{ANSI_RESET}")
    return asn_names

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file", help="Path to bgp-tools.json file")
    parser.add_argument("-p", "--include-single-source-paths", action="store_true", help="Include ASNs seen from only one LG vantage point")
    parser.add_argument("-m", "--missing", help="Comma-separated list of expected upstream ASNs to check")
    return parser.parse_args()

def main():
    args = parse_args()

    with open(args.input_file) as f:
        data = json.load(f)

    include_singles = args.include_single_source_paths
    expected_asns = set(args.missing.split(",")) if args.missing else set()
    asn_names = resolve_as_names(sorted(expected_asns)) if expected_asns else {}

    print()
    print(f"{'Prefix':<22}{'OriginAS':<9}Global Propagation from AS{TARGET_ASN}")

    for prefix, entries in data.items():
        if not entries:
            continue

        origin_as = entries[0]["as_path"][-1] if "as_path" in entries[0] else "?"
        upstream_counts = {}
        seen_paths = []

        for entry in entries:
            path = entry.get("as_path", [])
            if TARGET_ASN in path:
                idx = path.index(TARGET_ASN)
                if idx >= 1:
                    upstream = path[idx - 1]
                    upstream_counts[upstream] = upstream_counts.get(upstream, set())
                    upstream_counts[upstream].add(entry["source_asn"])
                    seen_paths.append((upstream, entry["source_asn"]))

        upstreams = []
        for asn, sources in upstream_counts.items():
            if len(sources) > 1:
                upstreams.append(asn)
            elif include_singles:
                upstreams.append(asn + "*")

        if args.missing:
            print(f"{prefix:<22}{origin_as:<9}")
            for expected_asn in sorted(expected_asns, key=int):
                full_name = asn_names.get(expected_asn, "???")
                name = full_name.split()[0] if full_name != "???" else "???"
                is_present = any(expected_asn == u.rstrip("*") for u in upstreams)
                label = f"{ANSI_GREEN}[ OK ]{ANSI_RESET}" if is_present else f"{ANSI_RED}[FAIL]{ANSI_RESET}"
                print(f"{'':<22}{'':<9}{expected_asn:<8} {name:<30}{label}")
            print()
        else:
            if not upstreams:
                print(f"{prefix:<22}{origin_as:<9}(no as-paths including {TARGET_ASN})")
            else:
                up_strs = []
                for u in upstreams:
                    mark = ""
                    if u.endswith("*"):
                        mark = f"{ANSI_RED}*{ANSI_RESET}"
                        u = u.rstrip("*")
                    up_strs.append(f"{u}{mark}")
                print(f"{prefix:<22}{origin_as:<9}{', '.join(up_strs)}")

if __name__ == "__main__":
    main()

