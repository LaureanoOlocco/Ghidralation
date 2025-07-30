
# @category GCL
"""idc wrapper"""

from ghidra.app.util.datatype import DataTypeSelectionDialog
from ghidra.framework.plugintool import PluginTool
from ghidra.util.data.DataTypeParser import AllowedDataTypes
from ghidra.program.model.data import DataTypeManager
from ghidra.program.model.data import DataType
from array import array
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.lang import OperandType
import ida_bytes
import cp
import ida_ua
import ida_name

SEGATTR_END = 8

get_name = ida_name.get_name
set_cmt = ida_bytes.set_cmt
get_wide_word = ida_bytes.get_wide_word
get_wide_dword = ida_bytes.get_wide_dword
get_wide_byte = ida_bytes.get_wide_byte

o_reg = 1
o_mem = 2

def get_segm_attr(segea, attr):
    """
    Get segment attributes...
    @param segea: any address within segment
    @param attr: segment attributes as per ida config, define by need.
    """
    minAddress = cp.currentProgram.minAddress.getOffset()
    fcp = FlatProgramAPI(cp.currentProgram)
    if attr == SEGATTR_END:
        end = cp.currentProgram.getMemory().getBlock(
            fcp.toAddr(segea+minAddress)).getEnd().getOffset()
        return end - minAddress


def GetString(address, length):
    """
    was ported to ida_bytes get_strlit_contents according to IDA
    address: linear address of the string
    length: length of the string in bytes including  null terminator
    return: a bytes-filled str object.
    """
    res = b""
    fcp = FlatProgramAPI(cp.currentProgram)
    try:
        res = fcp.getBytes(fcp.toAddr(address), length + 1)
        res = res.tolist()
        res = [i if i >= 0 else (256 + i) for i in res]
        res = array("B", res).tobytes()
    except Exception as ex:
        print("GetString failed: ", str(ex))
    finally:
        return res


def get_segm_name(ea):
    """
    @param ea: address
    returns: name of function's segment or empty string in case of failure
    """
    res = ""
    minAddress = cp.currentProgram.minAddress.getOffset()
    fcp = FlatProgramAPI(cp.currentProgram)
    try:
        res = cp.currentProgram.getMemory().getBlock(
            fcp.toAddr(ea+minAddress)).getName()
        if res == "EXTERNAL":
            res = "extern"
    except Exception as e:
        print("Failed to get segment", str(e))
    finally:
        return res


def get_func_name(func):
    minAddress = cp.currentProgram.minAddress.getOffset()
    fcp = FlatProgramAPI(cp.currentProgram)
    listing = cp.currentProgram.getListing()
    function = listing.getFunctionAt(fcp.toAddr(minAddress+func))
    return function.getName()


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
    fcp = FlatProgramAPI(cp.currentProgram)
    minAddress = cp.currentProgram.minAddress.getOffset()
    block = cp.currentProgram.getMemory().getBlock(
        fcp.toAddr(ea+minAddress)).getStart().getOffset()
    return block-minAddress


def get_segm_end(ea):
    fcp = FlatProgramAPI(cp.currentProgram)
    minAddress = cp.currentProgram.minAddress.getOffset()
    block = cp.currentProgram.getMemory().getBlock(
        fcp.toAddr(ea+minAddress)).getEnd().getOffset()
    return block-minAddress


def print_insn_mnem(ea):
    fcp = FlatProgramAPI(cp.currentProgram)
    minAddress = cp.currentProgram.minAddress.getOffset()
    listing = cp.currentProgram.getListing()
    codeUnit = listing.getCodeUnitAt(fcp.toAddr(minAddress+ea))
    if codeUnit is not None:
        res = str(codeUnit.getMnemonicString().lower())
        # print(res)
        return res
    else:
        return ""


def get_operand_value(ea, n):
    fcp = FlatProgramAPI(cp.currentProgram)
    minAddress = cp.currentProgram.minAddress.getOffset()
    listing = cp.currentProgram.getListing()
    codeUnit = listing.getCodeUnitAt(fcp.toAddr(minAddress+ea))
    if codeUnit is None:
        return -1
    insn = ida_ua.insn_t()
    inslen = ida_ua.decode_insn(insn, ea)
    if inslen == 0 or n >= codeUnit.getNumOperands():
        return -1
    fout = open("corresp.txt", "a")
    for inst in insn.ops:
        fout.write("{}:{}\n".format(codeUnit.toString(), vars(inst)))
    fout.close()
    op, value = insn.ops[n], -1
    if not op:
        return -1

    if op.type & OperandType.REGISTER:
        value = op.reg
    elif op.type & OperandType.SCALAR and not\
            (op.type & OperandType.ADDRESS):
        value = op.value
    if op.type & OperandType.CODE and \
            op.type & OperandType.ADDRESS:
        value = -1
    if op.type & OperandType.ADDRESS and op.type & OperandType.DATA:
        value = op.addr
    if op.type & OperandType.ADDRESS and op.type & OperandType.SCALAR:
        value = op.addr
    else:
        value = -1

    if value == 0x3c or value == 0x60:
        print("HERE")
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
    if newtype != '':

        tool = state.getTool()
        dtm = currentProgram.getDataTypeManager()
        selectionDialog = DataTypeSelectionDialog(tool, dtm, -1, AllowedDataTypes.FIXED_LENGTH)
        tool.showDialog(selectionDialog)
        dataType = newtype
        if dataType is not None:
            print("Chosen data type: " + str(dataType))
            pt = parse_decl(newtype, PT_SIL)
    if pt is None:
        # parsing failed
        return None
    pass


def set_name(ea, name, flags=0):
    pass


def op_stroff(ea, n, strid, delta):
    pass
