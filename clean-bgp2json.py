#!/usr/bin/env python3
import sys
import re
import json

def parse_bgp_blocks(filename):
    with open(filename, 'r') as f:
        content = f.read()

    blocks = content.strip().split("bgp.tools> show route ")
    result = {}

    for block in blocks:
        if not block.strip():
            continue

        lines = block.strip().splitlines()
        if not lines:
            continue

        # First line starts with the prefix
        prefix_match = re.match(r'([\d./]+)', lines[0])
        if not prefix_match:
            continue
        prefix = prefix_match.group(1)

        if prefix not in result:
            result[prefix] = []

        for line in lines[1:]:
            line = line.strip()
            match = re.match(
                r'\[\{AS(\d+)[^\}]*\}\s+[^\]]*\]\s+\[([^\]]+)\]\s+\{\[([^\]]*)\]\}',
                line
            )
            if match:
                source_asn = match.group(1)
                as_path = match.group(2).strip().split()
                communities = match.group(3).strip().split() if match.group(3).strip() else []

                result[prefix].append({
                    "source_asn": source_asn,
                    "as_path": as_path,
                    "communities": communities
                })

    return result

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: ./clean-bgp2json.py <bgp-clean.txt>")
        sys.exit(1)

    input_file = sys.argv[1]
    parsed_data = parse_bgp_blocks(input_file)
    print(json.dumps(parsed_data, indent=2))

