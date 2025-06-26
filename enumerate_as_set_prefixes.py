#!/usr/bin/env python3

import os
import sys
import subprocess
import time
import re

VENV_DIR = os.path.expanduser("~/.venv-irr-toolbox")

def ensure_venv_and_package():
    try:
        import irr_rpsl_client
        return
    except ImportError:
        pass

    if not os.path.isdir(VENV_DIR):
        print(f"[INFO] Creating virtual environment at {VENV_DIR}")
        subprocess.run([sys.executable, "-m", "venv", VENV_DIR], check=True)

    pip_path = os.path.join(VENV_DIR, "bin", "pip")
    print(f"[INFO] Installing irr-rpsl-client in virtual environment...")
    subprocess.run([pip_path, "install", "--quiet", "irr-rpsl-client"], check=True)

    python_path = os.path.join(VENV_DIR, "bin", "python")
    print(f"[INFO] Re-executing script using virtual environment...")
    os.execv(python_path, [python_path] + sys.argv)

ensure_venv_and_package()

from irr_rpsl_client.client import RemoteClient
import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Enumerate prefixes from IRR aut-num or AS-SET objects (IPv4 only)"
    )
    parser.add_argument("object", help="AS-SET or aut-num to enumerate")
    parser.add_argument("-s", "--source", help="IRR source server (default: rr.ntt.net)", default="rr.ntt.net")
    parser.add_argument("-i", "--info", action="store_true", help="Verbose route object info")
    parser.add_argument("-w", "--warning", action="store_true", help="Show warnings")
    parser.add_argument("-c", "--chain", action="store_true", help="Print parent->child ancestry")
    parser.add_argument("--pl-vyos", action="store_true", help="Emit VyOS prefix-list output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress output")
    parser.add_argument("--agg", action="store_true", help="Aggregate output prefixes")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    return parser.parse_args()

def extract_prefixes_from_autnum(client, asn):
    return {r["prefix"] for r in client.routes_for_origin(f"AS{asn}")}

def enumerate_as_set(client, as_set, seen=None):
    if seen is None:
        seen = set()
    asn_list = set()
    members = client.get_as_set_members(as_set)
    for member in members:
        if member in seen:
            continue
        seen.add(member)
        if member.startswith("AS") and member[2:].isdigit():
            asn_list.add(member[2:])
        elif ":" in member or "-" in member:
            nested_asns = enumerate_as_set(client, member, seen)
            asn_list.update(nested_asns)
    return asn_list

def main():
    args = parse_arguments()
    start_time = time.time()
    client = RemoteClient(args.source)

    if re.match(r"^AS\d+$", args.object, re.IGNORECASE):
        if args.debug:
            print(f"[DEBUG] Detected aut-num: {args.object}")
        prefixes = extract_prefixes_from_autnum(client, args.object[2:])
    else:
        if args.debug:
            print(f"[DEBUG] Detected AS-SET: {args.object}")
        asns = enumerate_as_set(client, args.object)
        if args.debug:
            print(f"[DEBUG] Found {len(asns)} unique ASNs from AS-SET")
        prefixes = set()
        for asn in asns:
            pfxs = extract_prefixes_from_autnum(client, asn)
            prefixes.update(pfxs)
            if args.debug:
                print(f"[DEBUG] ASN AS{asn} yielded {len(pfxs)} prefixes")

    if not args.quiet:
        for prefix in sorted(prefixes):
            print(prefix)

    if args.debug:
        print(f"Completed in {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    main()
