#!/bin/bash
SESSION=bgptools
OUTPUT_FILE="bgptools-output.txt"
COMMANDS=(
  "show route 64.40.23.0/24 short match 19366"
  "show route 44.76.16.0/24 short match 19366"
)

# Start detached tmux session and SSH in
tmux new-session -d -s "$SESSION" "ssh -tt lg@bgp.tools"

# Wait for banner and prompt
sleep 6

# Check if tmux session is still alive
if ! tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "ERROR: tmux session died before we could send commands"
  exit 1
fi

# Send commands
for cmd in "${COMMANDS[@]}"; do
  tmux send-keys -t "$SESSION" "$cmd" C-m
  sleep 2
done

# Send Ctrl-D to terminate session
tmux send-keys -t "$SESSION" C-d

# Wait for shutdown
sleep 3

# Capture pane if still active
if tmux has-session -t "$SESSION" 2>/dev/null; then
  tmux capture-pane -t "$SESSION" -p > "$OUTPUT_FILE"
  tmux kill-session -t "$SESSION"
  echo "Output saved to $OUTPUT_FILE"
else
  echo "ERROR: session exited before capture, retry with longer delays"
fi

