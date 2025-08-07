# @category GCL
"""idc wrapper"""

from ghidra.app.util.datatype import DataTypeSelectionDialog
from ghidra.framework.plugintool import PluginTool
from ghidra.util.data.DataTypeParser import AllowedDataTypes
from ghidra.program.model.data import DataTypeManager
from ghidra.program.model.data import DataType
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.data import DataUtilities
from ghidra.program.model.data import DataTypePath
from ghidra.program.model.data import Structure
from ghidra.util.data import DataTypeParser
from ghidra.util.task import TaskMonitor
from ghidra.program.model.lang import OperandType
from array import array
import ida_bytes
import cp
import ida_ua
import ida_name

SEGATTR_END = 8
BADADDR = -1
USE_DEFAULT_LENGTH = 0

# get_name = ida_name.get_name
set_cmt = ida_bytes.set_cmt
get_wide_word = ida_bytes.get_wide_word
get_wide_dword = ida_bytes.get_wide_dword
get_wide_byte = ida_bytes.get_wide_byte

o_reg = 1
o_mem = 2


def get_program_context():
    """
    Get reusable program context: FlatProgramAPI and minAddress.

    @return: (program_api, minAddress)
    """
    program_api = FlatProgramAPI(cp.currentProgram)
    min_address = cp.currentProgram.getMinAddress().getOffset()
    return program_api, min_address


def get_memory_block_at_address(ea):
    """
    Get the memory block containing the given EA.

    @param ea: IDA-style offset (relative to minAddress)
    @return: MemoryBlock object or None if not found
    """
    program_api, min_address = get_program_context()
    addr = program_api.toAddr(ea + min_address)
    return cp.currentProgram.getMemory().getBlock(addr)


def get_segm_attr(ea, attr):
    """
    Get segment attribute value by EA.

    @param ea: any address in the segment (IDA-style EA)
    @param attr: attribute (currently only SEGATTR_END supported)
    @return: attribute value (IDA-style EA), or BADADDR if invalid
    """
    block = get_memory_block_at_address(ea)
    if block is None:
        return BADADDR

    _, min_address = get_program_context()

    if attr == SEGATTR_END:
        return block.getEnd().getOffset() - min_address

    print(f"[WARN] Unsupported segment attribute: {attr}")
    return BADADDR


def GetString(address, length):
    """
    was ported to ida_bytes get_strlit_contents according to IDA
    address: linear address of the string
    length: length of the string in bytes including  null terminator
    return: a bytes-filled str object.
    """
    res = b""
    program_api = FlatProgramAPI(cp.currentProgram)
    try:
        res = program_api.getBytes(program_api.toAddr(address), length + 1)
        res = res.tolist()
        res = [i if i >= 0 else (256 + i) for i in res]
        res = array("B", res).tobytes()
    except Exception as ex:
        print("GetString failed: ", str(ex))
    finally:
        return res


def get_segm_name(ea):
    """
    Get name of a segment

    @param ea: any address in the segment

    @return: segment name
             "" - no segment at the specified address
    """
    block = get_memory_block_at_address(ea)
    if block is None:
        return ""

    name = block.getName()
    if name == "EXTERNAL":
        return "extern"

    return name


def get_func_name(ea):
    """
    Retrieve function name

    @param ea: any address belonging to the function
    @return: null string - function doesn't exist
             otherwise returns function name
    """
    program_api, min_address = get_program_context()
    listing = cp.currentProgram.getListing()
    func = listing.getFunctionAt(program_api.toAddr(min_address + ea))

    if func is None:
        return ""

    return func.getName()


def auto_wait():
    pass


def import_type(idx, type_name):
    if type_name == "EFI_GUID":
        return 1
    elif type_name == "EFI_SYSTEM_TABLE":
        return 2
    elif type_name == "EFI_RUNTIME_SERVICES":
        return 3
    elif type_name == "EFI_BOOT_SERVICES":
        return 4
    else:
        return 5


def get_segm_start(ea):
    """
    Get start address of a segment.

    @param ea: any address in the segment
    @return: start of segment
             BADADDR - the specified address doesn't belong to any segment
    """
    block = get_memory_block_at_address(ea)
    if block is None:
        return BADADDR

    _, min_address = get_program_context()
    return block.getStart().getOffset() - min_address


def get_segm_end(ea):
    """
    Get end address of a segment

    @param ea: any address in the segment
    @return: end of segment
             BADADDR - the specified address doesn't belong to any segment
    """
    block = get_memory_block_at_address(ea)
    if block is None:
        return BADADDR

    _, min_address = get_program_context()
    return block.getEnd().getOffset() - min_address


def print_insn_mnem(ea):
    fcp = FlatProgramAPI(cp.currentProgram)
    minAddress = cp.currentProgram.minAddress.getOffset()
    listing = cp.currentProgram.getListing()
    codeUnit = listing.getCodeUnitAt(fcp.toAddr(minAddress + ea))
    if codeUnit is not None:
        res = str(codeUnit.getMnemonicString().lower())
        # print(res)
        return res
    else:
        return ""


def get_operand_value(ea, n):
    """
    Get number used in the operand

    This function returns an immediate number used in the operand

    @param ea: linear address of instruction
    @param n: the operand number

    @return: value
        operand is an immediate value  => immediate value
        operand has a displacement     => displacement
        operand is a direct memory ref => memory address
        operand is a register          => register number
        operand is a register phrase   => phrase number
        otherwise                      => -1
    """
    program_api, min_address = get_program_context()
    listing = cp.currentProgram.getListing()
    code_unit = listing.getCodeUnitAt(program_api.toAddr(ea + min_address))

    if code_unit is None:
        return -1

    insn = ida_ua.insn_t()
    inslen = ida_ua.decode_insn(insn, ea)
    if inslen == 0 or n >= code_unit.getNumOperands():
        return -1

    op = insn.ops[n]
    if not op:
        return -1

    value = -1

    if op.type & OperandType.REGISTER:
        value = op.reg  # Register number
    elif op.type & OperandType.SCALAR and not (op.type & OperandType.ADDRESS):
        value = op.value  # Immediate value or displacement
    elif op.type & OperandType.ADDRESS:
        if op.type & OperandType.DATA or op.type & OperandType.SCALAR:
            value = op.addr  # Direct memory reference
        elif op.type & OperandType.CODE:
            value = -1  # Code reference, not handled here

    return value


def next_head(ea, maxea=cp.currentProgram.maxAddress.getOffset()):
    return ida_bytes.next_head(ea, maxea)


def prev_head(ea, minea=cp.currentProgram.minAddress.getOffset()):
    return ida_bytes.prev_head(ea, maxea)


def get_struc_id(struc):
    if struc == "EFI_GUID":
        return 1
    elif struc == "EFI_BOOT_SERVICES":
        return 2


def SetType(ea, newtype):
    """
    Set type of function/variable

    @param ea: the address of the object
    @param newtype: the type string in C declaration form.
                    Must contain the closing ';'
                    If specified as an empty string, the
                    item associated with 'ea' will be deleted.

    @return: 1-ok, 0-failed.
    """
    try:
        fpa, min_addr = get_program_context()
        addr = fpa.toAddr(min_addr + ea)
        listing = cp.currentProgram.getListing()

        if newtype == "":
            # Delete any defined data at that address
            existing = listing.getDefinedDataAt(addr)
            if existing:
                listing.clearCodeUnits(addr, addr, False)
            return 1

        parser = DataTypeParser(fpa, None)
        dt = parser.parse(newtype)

        DataUtilities.createData(
            cp.currentProgram,
            addr,
            dt,
            USE_DEFAULT_LENGTH,
            False,
            DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA,
        )
        return 1

    except Exception as e:
        print(f"[SetType] Failed to apply type '{newtype}' at {ea:#X}: {e}")
        return 0


def get_name(ea, flags=0):
    """
    Get name at the specified address

    @param ea: linear address
    @param gtn_flags: how exactly the name should be retrieved.
                      combination of GN_ bits
    """
    pass


def set_name(ea, name, flags=0):
    """
    Rename an address

    @param ea: linear address
    @param name: new name of address. If name == "", then delete old name
    @param flags: combination of SN_... constants
    @return: 1-ok, 0-failed.
    """
    pass


def op_stroff(ea, n, strid, delta):
    """
    Emulates idc.op_stroff in Ghidra.

    Convert operand to an offset in a structure.

    @param ea: linear address of the instruction.
    @param n: operand index.
              -  0: the first operand
              -  1: the second, third, and all other operands
              - -1: all operands
    @param strid: ID of a structure type (can be a name or a Structure object in Ghidra).
    @param delta: struct offset delta. Usually 0, represents the difference
                  between the structure base and the pointer into the structure.
    @return: True if applied successfully, False on error.
    """
    program_api, min_address = get_program_context()
    listing = cp.currentProgram.getListing()
    dtm = cp.currentProgram.getDataTypeManager()

    addr = program_api.toAddr(ea)
    insn = listing.getInstructionAt(addr)
    if insn is None:
        print(f"[op_stroff] No instruction found at {ea:#X}")
        return False

    # Resolve the structure
    if isinstance(strid, Structure):
        struct = strid
    elif isinstance(strid, str):
        struct = dtm.getDataType("/" + strid)
    else:
        print("[op_stroff] Unsupported strid type (expected string or Structure).")
        return False

    if struct is None or not isinstance(struct, Structure):
        print(f"[op_stroff] No valid structure found for '{strid}'")
        return False

    # Determine which operands to process
    indices = range(insn.getNumOperands()) if n == -1 else [n]

    for idx in indices:
        try:
            operand_type = insn.getOperandType(idx)
            if not OperandType.isAddress(operand_type):
                continue

            operand_refs = insn.getOperandReferences(idx)
            if not operand_refs:
                continue

            target = operand_refs[0].getToAddress()

            # Create the structure at the referenced address
            DataUtilities.createData(
                cp.currentProgram,
                target,
                struct,
                delta,
                False,
                DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA,
            )

            # Add a comment (optional, visual aid)
            insn.setComment(CodeUnit.EOL_COMMENT, f"{struct.getName()}+0x{delta:X}")

        except Exception as e:
            print(f"[op_stroff] Error applying on operand {idx}: {e}")
            return False

    return True
