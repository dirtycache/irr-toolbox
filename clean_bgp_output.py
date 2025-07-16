#!/usr/bin/env python3

import re
import sys

if len(sys.argv) != 3:
    print("Usage: ./clean_bgp_output.py <input_file> <output_file>")
    sys.exit(1)

input_file = sys.argv[1]
output_file = sys.argv[2]

ansi_escape = re.compile(r'\x1B\[[0-9;]*[A-Za-z]')
banner_line = re.compile(r'^[\u2580\u2588 ]+$')
motd_patterns = [
    re.compile(r"This session is supported by:"),
    re.compile(r"For more information about AS[0-9]+, check out"),
]
prompt_re = re.compile(r'^bgp\.tools>')
show_route_re = re.compile(r'^bgp\.tools> show route ')

blocks = []
current_block = []
collecting = False

with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        # Strip ANSI codes and clean line
        line = ansi_escape.sub('', line).replace('\r', '').rstrip()
        if not line.strip():
            continue
        if banner_line.match(line):
            continue
        if any(p.search(line) for p in motd_patterns):
            continue

        if show_route_re.match(line):
            # Store the previous block if it had real output
            if collecting and len(current_block) > 1:
                blocks.append('\n'.join(current_block))
            current_block = [line]
            collecting = True
        elif prompt_re.match(line):
            # Ignore idle prompts
            continue
        elif collecting:
            current_block.append(line)

# Add last valid block
if collecting and len(current_block) > 1:
    blocks.append('\n'.join(current_block))

with open(output_file, 'w') as out:
    out.write('\n\n'.join(blocks) + '\n')
