# -*- coding: utf-8 -*-
# test/test_set_name.py
# @category GCL
# @runtime PyGhidra

"""
Initial test suite for set_name() in Ghidralation.
Run from Ghidra with a program loaded.
"""

import sys
import os
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import StructureDataType
from ghidra.program.model.data import ByteDataType, DWordDataType


# Add src/ to the path
script_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(os.path.dirname(script_dir), "src")
sys.path.insert(0, src_dir)

# Set currentProgram
import cp

cp.currentProgram = currentProgram

# Basic info about the loaded program
program = currentProgram

# ================================
# Welcome banner
# ================================
print(
    f"""
================================================================
                TEST SUITE - (Ghidralation)
----------------------------------------------------------------
Run this with a program loaded in Ghidra.

=== Program Information ===
Program Name             : {program.getName()}
Executable Path          : {program.getExecutablePath()}
Language                 : {program.getLanguage()}
Compiler                 : {program.getCompilerSpec()}
Minimum Address          : {program.getMinAddress()}
Maximum Address          : {program.getMaxAddress()}
================================================================
    """
)

# Import modules
import ida_name
from ida_name import set_name, get_name, SN_NOCHECK, SN_CHECK
import idc


class TestSetName:
    def __init__(self):
        self.program = currentProgram
        self.symbol_table = self.program.getSymbolTable()
        self.address_factory = self.program.getAddressFactory()
        self.default_space = self.address_factory.getDefaultAddressSpace()
        self.min_addr = self.program.getMinAddress().getOffset()
        self.max_addr = self.program.getMaxAddress().getOffset()

        # Result counters
        self.tests_passed = 0
        self.tests_failed = 0
        self.test_addresses = []  # For cleanup at the end

        print(">>> Starting tests for ida_name.set_name()")
        print(f"    Loaded Program         : {self.program.getName()}")
        print(f"    Address Range          : 0x{self.min_addr:x} - 0x{self.max_addr:x}")
        print("================================================================")

    def get_test_address(self, offset=0x100):
        """Get a valid address for testing."""
        addr = self.min_addr + offset
        if addr > self.max_addr:
            addr = self.min_addr + (offset % 0x100)

        # Avoid conflicts using unique addresses
        while addr in self.test_addresses:
            addr += 0x10
            if addr > self.max_addr:
                addr = self.min_addr

        self.test_addresses.append(addr)
        return addr

    def assert_test(self, condition, test_name, error_msg=""):
        """Helper to handle assertions and counting."""
        if condition:
            print(f"✓ PASS: {test_name}")
            self.tests_passed += 1
        else:
            print(f"✗ FAIL: {test_name}")
            if error_msg:
                print(f"    Error: {error_msg}")
            self.tests_failed += 1

    def cleanup_test_address(self, addr):
        """Cleans up a symbol from a test address."""
        try:
            set_name(addr, "", 0)
        except:
            pass

    # ================================
    # BASIC TESTS
    # ================================

    def test_01_import(self):
        """Verify that the module is imported correctly."""
        print("\n[TEST 01] Module import")
        print("----------------------------------------------------------------")

        self.assert_test(callable(set_name), "set_name is callable")
        self.assert_test(callable(get_name), "get_name is callable")
        self.assert_test(isinstance(SN_CHECK, int), "SN_* constants are defined")

    def test_basic_symbol_creation(self):
        """Create, verify, and delete a basic symbol."""
        print("\n[TEST] Basic symbol creation")
        print("----------------------------------------------------------------")
        addr = self.get_test_address()

        print(f"Selected test address: 0x{addr:x}")

        try:
            result = set_name(addr, "test_symbol", SN_NOCHECK)
            if result != 1:
                print("Error: Could not create symbol (result != 1)")
                return
            print(f"Symbol successfully created at 0x{addr:x}")

            name = get_name(addr, 0)
            if "test_symbol" not in name:
                print(f"Error: Retrieved name does not match (got: {name})")
                return
            print(f"Successful verification: retrieved name = {name}")

            result = set_name(addr, "", 0)
            if result != 1:
                print("Error: Could not delete the symbol")
                return
            print("Symbol successfully deleted")
        except Exception as e:
            print(f"Exception during test: {e}")

    def run(self):
        """Run the test suite."""
        print("\n================= BEGIN TESTS =================")
        self.test_01_import()
        self.test_basic_symbol_creation()
        print("\n================= END OF TESTS ====================")


class TestOpStroff:
    def __init__(self):
        self.program = currentProgram
        self.listing = self.program.getListing()
        self.dtm = self.program.getDataTypeManager()
        self.min_addr = self.program.getMinAddress().getOffset()
        self.max_addr = self.program.getMaxAddress().getOffset()

        self.tests_passed = 0
        self.tests_failed = 0

        print(">>> Starting tests for idc.op_stroff()")
        print(f"    Loaded Program         : {self.program.getName()}")
        print(f"    Address Range          : 0x{self.min_addr:x} - 0x{self.max_addr:x}")
        print("================================================================")

    def assert_test(self, condition, test_name, error_msg=""):
        """Helper to handle assertions and counting."""
        if condition:
            print(f"✓ PASS: {test_name}")
            self.tests_passed += 1
        else:
            print(f"✗ FAIL: {test_name}")
            if error_msg:
                print(f"    Error: {error_msg}")
            self.tests_failed += 1

    def get_first_instruction(self):
        """Return the first valid instruction address in the program."""
        instructions = self.listing.getInstructions(self.program.getMinAddress(), True)
        if instructions.hasNext():
            return instructions.next().getAddress().getOffset()
        return None

    # ================================
    # BASIC TESTS
    # ================================
    def test_01_import(self):
        """Verify that the module is imported correctly."""
        print("\n[TEST 01] Module import")
        print("----------------------------------------------------------------")
        self.assert_test(callable(idc.op_stroff), "idc.op_stroff is callable")

    def test_basic_op_stroff(self):
        """Create a dummy struct and apply op_stroff."""
        print("\n[TEST] Basic op_stroff application")
        print("----------------------------------------------------------------")

        ea = self.get_first_instruction()
        self.assert_test(ea is not None, "Found a valid instruction address")
        if ea is None:
            print("[DEBUG] No valid instruction found, skipping test.")
            return

        print(f"Selected instruction address: 0x{ea:x}")

        # Create a dummy structure for testing
        struct_name = "TEST_STRUCT"
        struct = self.dtm.getDataType("/" + struct_name)
        if struct is None:
            struct = StructureDataType(struct_name, 0)
            struct.add(ByteDataType.dataType, 1, "field1", None)
            struct.add(DWordDataType.dataType, 4, "field2", None)
            struct = self.dtm.addDataType(struct, None)
            print(f"Structure '{struct_name}' created.")

        # Apply op_stroff on operand 0
        result = idc.op_stroff(ea, 0, struct.getName(), 0)
        self.assert_test(result, "op_stroff applied successfully")

        if not result:
            print("[DEBUG] op_stroff failed, skipping comment verification.")
            return

        # Verify comment was added
        insn = self.listing.getInstructionAt(toAddr(ea))
        if insn is None:
            self.assert_test(
                False, "Instruction still exists at address after op_stroff"
            )
            return

        comment = insn.getComment(0)
        self.assert_test(
            comment is not None and struct_name in comment,
            "Operand comment contains structure name",
            f"Comment: {comment}",
        )

    def run(self):
        """Run the test suite."""
        print("\n================= BEGIN TESTS =================")
        self.test_01_import()
        self.test_basic_op_stroff()
        print("\n================= END OF TESTS ====================")
        print(f"Tests Passed: {self.tests_passed}")
        print(f"Tests Failed: {self.tests_failed}")


if __name__ == "__main__":
    tester = TestOpStroff()
    tester.run()
