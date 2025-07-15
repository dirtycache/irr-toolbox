#!/usr/bin/env bash
set -euo pipefail

echo "[1/4] Scraping Looking Glass data..."
./bgp-batch.exp > bgp-raw.txt

echo "[2/4] Cleaning output..."
./clean-lg-output.sh bgp-raw.txt > bgp-clean.txt

echo "[3/4] Parsing to JSON..."
./clean-bgp2json.py bgp-clean.txt > bgp-tools.json

echo "[4/4] Analyzing upstreams..."
./check_transit_advertisement.py bgp-tools.json

