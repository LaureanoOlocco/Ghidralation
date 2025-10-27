#!/bin/bash
# =============================================================================
# run_test.sh - Ghidralation Test Runner
# =============================================================================
# This script automates test execution for the Ghidralation project using
# Ghidra in headless mode. It loads a test binary and executes a Python
# script that validates the implemented functionalities.
# =============================================================================

# System path configuration
GHIDRA_SUPPORT="/home/eclypsium/Documents/ghidra/ghidra_11.4.1_PUBLIC/support"   # Ghidra support directory
PROJECT_DIR="/home/eclypsium/Documents/Ghidralation/project-test"                # Ghidra project directory
PROJECT_NAME="crypto-binary"                                                     # Ghidra project name
BINARY_NAME="findcrypt_binary"                                                   # Binary to analyze (note: actual file is crypt_binary)
SCRIPT_PATH="/home/eclypsium/Documents/Ghidralation/test/test_suite.py"          # Python test script path

# Execute Ghidra in headless mode
# --headless: Run without GUI
# -process: Load and process the specified binary
# -postScript: Execute Python script after loading the binary
"$GHIDRA_SUPPORT/pyghidraRun" --headless "$PROJECT_DIR" "$PROJECT_NAME" \
  -process "$BINARY_NAME" \
  -postScript "$SCRIPT_PATH"
