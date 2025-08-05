#!/bin/bash
GHIDRA_SUPPORT="/home/aurean/ghidra/ghidra_11.4_PUBLIC/support"
PROJECT_DIR="/home/aurean/GhidraProjects"
PROJECT_NAME="syms2elf"
BINARY_NAME="crypto_binary"
SCRIPT_PATH="/home/aurean/Desktop/Ghidralation/test/test_suite.py"

"$GHIDRA_SUPPORT/pyghidraRun" --headless "$PROJECT_DIR" "$PROJECT_NAME" \
  -process "$BINARY_NAME" \
  -postScript "$SCRIPT_PATH"