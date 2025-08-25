#!/bin/bash
GHIDRA_SUPPORT="/home/eclypsium/Documents/ghidra/ghidra_11.4.1_PUBLIC/support"
PROJECT_DIR="/home/eclypsium/Documents/GhidraProjects"
PROJECT_NAME="syms2elf"
BINARY_NAME="crypto_binary"
SCRIPT_PATH="/home/eclypsium/Documents/Ghidralation/test/test_suite.py"

"$GHIDRA_SUPPORT/pyghidraRun" --headless "$PROJECT_DIR" "$PROJECT_NAME" \
  -process "$BINARY_NAME" \
  -postScript "$SCRIPT_PATH"