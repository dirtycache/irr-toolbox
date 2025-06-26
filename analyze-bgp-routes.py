#!/usr/bin/env python3

import os
import sys
import subprocess
import json
import time
import datetime
import ssl
import warnings

# === VENV MANAGEMENT ===
if "INSIDE_VENV" not in os.environ:
    try:
        import requests
        import urllib3
    except ImportError:
        print("Python module import 'requests' r 'urllib3' failed, so punting to venv")
        venv_path = os.path.expanduser("~/.venv_tmp_irr-toolbox_anal_recv")
        if os.path.exists(venv_path):
            age = time.time() - os.path.getmtime(venv_path)
            if age < 3600:
                print("Using existing virtual environment...")
            else:
                print("Removing old venv...")
                subprocess.run(["rm", "-rf", venv_path])
            if not os.path.exists(venv_path):
                print(f"Creating new virtual environment at {venv_path} ...")
                subprocess.run([sys.executable, "-m", "venv", venv_path])
                subprocess.run([f"{venv_path}/bin/pip", "install", "--upgrade", "pip", "setuptools"])
                subprocess.run([f"{venv_path}/bin/pip", "install", "requests", "urllib3"])
            print(f"Re-running script inside virtual environment using {venv_path}/bin/python ...")
            os.execve(
                f"{venv_path}/bin/python",
                [f"{venv_path}/bin/python"] + sys.argv,
                dict(os.environ, INSIDE_VENV="1")
            )
        else:
            sys.exit("Cannot continue without required modules.")

# === IMPORTS ===
import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(category=InsecureRequestWarning)

import argparse
import ipaddress

# === CONSTANTS ===

bogon_networks = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4"
]

TIER1_ASNs = [
    174,
    209,
    286,
    701,
    7018,
    1239,
    1299,
    2828,
    2914,
    3257,
    3320,
    3356,
    5511,
    6453,
    6461,
    6762,
    7018
]

# === FUNCTIONS ===

def get_api_key(router):
    keyfile = os.path.expanduser(f"~/{router}.api")
    if os.path.exists(keyfile):
        with open(keyfile) as f:
            return f.read().strip()
    print("Error: must provide API key via --key or VYOS_API_KEY or ~/<router>.api")
    sys.exit(1)

def get_local_asn(router, api_key, verify_ssl):
    payload = {"op": "showConfig", "path": ["protocols", "bgp", "system-as"]}
    try:
        r = requests.post(
            f"https://{router}/retrieve",
            files={
                "data": (None, json.dumps(payload)),
                "key": (None, api_key),
            },
            verify=verify_ssl
        )
        if r.ok:
            return r.json().get("data", {}).get("system-as", "UNKNOWN")
    except Exception:
        pass
    return "UNKNOWN"

def get_bgp_summary(router, api_key, verify_ssl):
    payload = {"op": "show", "path": ["bgp", "ipv4", "summary"]}
    try:
        r = requests.post(
            f"https://{router}/show",
            files={
                "data": (None, json.dumps(payload)),
                "key": (None, api_key),
            },
            verify=verify_ssl
        )
        if r.ok:
            return r.json().get("data", "")
    except Exception:
        pass
    return ""

def parse_bgp_summary(data):
    peers = []
    lines = data.splitlines()
    capture = False
    for line in lines:
        line = line.strip()
        if line.startswith("Neighbor"):
            capture = True
            continue
        if capture and line and not line.startswith("Total"):
            parts = line.split()
            if len(parts) >= 3:
                ip = parts[0]
                asn = int(parts[2])
                peers.append((ip, asn))
    return peers

def get_received_prefixes(router, api_key, neighbor_ip, verify_ssl):
    payload = {"op": "show", "path": ["bgp", "ipv4", "neighbors", neighbor_ip, "received-routes"]}
    try:
        r = requests.post(
            f"https://{router}/show",
            files={
                "data": (None, json.dumps(payload)),
                "key": (None, api_key),
            },
            verify=verify_ssl
        )
        if r.ok:
            return r.json().get("data", "")
    except Exception:
        pass
    return ""

def parse_received_routes(route_output):
    prefixes = []
    for line in route_output.splitlines():
        line = line.strip()
        if not line or line.startswith("Network") or line.startswith("BGP") or "Next Hop" in line:
            continue

        parts = line.split()
        if not parts or parts[-1] not in ("i", "e", "?"):
            continue  # skip non-finalized routes

        try:
            prefix = parts[1] if parts[0] in ("*", "*>") else parts[0]
            if "/" not in prefix:
                continue

            # Find AS path by skipping over non-ASN fields
            path = []
            seen_zero_weight = False
            for tok in parts:
                if tok.isdigit():
                    val = int(tok)
                    if not seen_zero_weight:
                        seen_zero_weight = (val == 0)
                        continue
                    path.append(val)

            prefixes.append((prefix, path))
        except Exception:
            continue

    return prefixes

def is_bogon(prefix):
    try:
        net = ipaddress.ip_network(prefix, strict=False)
        return any(net.subnet_of(ipaddress.ip_network(bn)) for bn in bogon_networks)
    except ValueError:
        return False

def is_transit_leak(path):
    tier1_hops = [asn for asn in path if asn in TIER1_ASNs]
    for i in range(len(tier1_hops) - 1):
        start = path.index(tier1_hops[i])
        end = path.index(tier1_hops[i+1])
        if any(asn not in TIER1_ASNs for asn in path[start+1:end]):
            return True
    return False

# === MAIN ===

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("router", help="Router hostname or IP")
    parser.add_argument("-t", "--type", choices=["vyos"], default="vyos")
    parser.add_argument("-i", "--include", type=int, help="Only include this ASN")
    parser.add_argument("-k", "--insecure", action="store_true", help="Ignore SSL cert errors")
    parser.add_argument("--show-ok", action="store_true", help="Show OK prefixes in output")
    args = parser.parse_args()

    router = args.router
    verify_ssl = not args.insecure
    api_key = get_api_key(router)

    print(f">> Connecting to {router} to retrieve local ASN via API...")
    local_asn = get_local_asn(router, api_key, verify_ssl)
    print(f">> Local ASN is {local_asn}")

    print(f">> Connecting to {router} to gather BGP IPv4 summary...")
    summary = get_bgp_summary(router, api_key, verify_ssl)
    if not summary:
        print("Error fetching BGP summary")
        return

    peers = parse_bgp_summary(summary)
    print(f"Found {len(peers)} BGP neighbors.\n")

    include_set = {args.include} if args.include else set()
    excluded = [f"{ip} (AS{asn})" for ip, asn in peers if include_set and asn not in include_set]
    if excluded:
        print(f"Skipping {len(excluded)} neighbors(s) with ASN not within include list:")
        for e in excluded:
            print(f"  - {e}")
    else:
        print("Skipping 0 neighbors(s) with ASN not within include list:")

    print("\nAnalyzing {} peer(s)...\n".format(len(peers) - len(excluded)))
    for ip, asn in peers:
        if include_set and asn not in include_set:
            continue
        routes = get_received_prefixes(router, api_key, ip, verify_ssl)
        prefixes = parse_received_routes(routes)
        print(f">>> Neighbor {ip} (AS{asn}) : [{len(prefixes)} prefixes]")

        for prefix, path in prefixes:
            verdict_label = "ROUTE_OK"

            if prefix in ("0.0.0.0/0", "::/0"):
                if path and all(p == asn for p in path):
                    verdict_label = "ROUTE_OK"
                else:
                    verdict_label = "BAD_ORIG_DEFAULT"
            elif is_bogon(prefix):
                verdict_label = "BOGON_PREFIX"
            elif "/" in prefix and int(prefix.split("/")[1]) > 24:
                verdict_label = "PREFIX_TOOLONG"
            elif is_transit_leak(path):
                verdict_label = "TRANSIT_LEAK"

            if verdict_label != "ROUTE_OK" or args.show_ok:
                print(f"    [{verdict_label.center(16)}]   {prefix:<23} {' '.join(str(asn) for asn in path)}")

if __name__ == "__main__":
    main()

