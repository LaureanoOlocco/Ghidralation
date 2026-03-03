
# @category GCL

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.lang import OperandType
import cp

REGS = {'RAX': 0, 'EAX': 0, 'AX': 0,
        'RCX': 1, 'ECX': 1, 'CX': 1,
        'RDX': 2, 'EDX': 2, 'DX': 2,
        'RBX': 3, 'EBX': 3, 'BX': 3,
        'RSP': 4, 'ESP': 4, 'SP': 4,
        'RBP': 5, 'EBP': 5, 'BP': 5,
        'RSI': 6, 'ESI': 6, 'SI': 6,
        'RDI': 7, 'EDI': 7, 'DI': 7,
        'R8': 8, 'R8D': 8, 'R8B': 8, 'R8W': 8,
        'R9': 9, 'R9D': 9, 'R9B': 9, 'R9W': 9,
        'R10': 10, 'R10D': 10, 'R10B': 10, 'R10W': 10,
        'R11': 11, 'R11D': 11, 'R11B': 11, 'R11W': 11,
        'R12': 12, 'R12D': 12, 'R12B': 12, 'R12W': 12,
        'R13': 13, 'R13D': 13, 'R13B': 13, 'R13W': 13,
        'R14': 14, 'R14D': 14, 'R14B': 14, 'R14W': 14,
        'R15': 15, 'R15D': 15, 'R15B': 15, 'R15W': 15,
        'AL': 16, 'CL': 17, 'DL': 18, 'BL': 19, 'SPL': 24,
        'BPL': 25, 'SIL': 26, 'DIL': 27}


class insn_t:
    def __init__(self):
        ops = []

class operand:
    def __init__(self):
        addr = None
        value = None
        reg = None
        phrase = None
        type = None
    
def decode_insn(insn, ea):
    """Fill insn according to the given ea
    @returns: length of instruction if successfull else 0
    """
    listing = cp.currentProgram.getListing()
    minAddress = cp.currentProgram.minAddress.getOffset()
    fcp = FlatProgramAPI(cp.currentProgram)
    if listing.getCodeUnitAt(fcp.toAddr(minAddress+ea))==None:
        return 0
    codeUnit = listing.getCodeUnitAt(fcp.toAddr(minAddress+ea))

    insn.ops = [i for i in range(codeUnit.getNumOperands())]

    for i in range(len(insn.ops)):
        op = operand()
        op.type = codeUnit.getOperandType(i)
        if op.type & OperandType.REGISTER:
            reg = str(codeUnit.getOpObjects(i)[0])
            op.reg = REGS[reg]
        if op.type & OperandType.SCALAR and not\
            (op.type & OperandType.ADDRESS):
            op.value = int(str(codeUnit.getOpObjects(i)[0]), 16)
        if op.type & OperandType.CODE and \
            op.type & OperandType.ADDRESS:
            # o_near
            op.addr = -1
        if op.type & OperandType.ADDRESS and op.type & OperandType.DATA:
            op.addr = codeUnit.getOpObjects(i)[0].getOffset()-minAddress
        if op.type & OperandType.ADDRESS and op.type & OperandType.SCALAR:
            op.addr = codeUnit.getOpObjects(i)[0].getUnsignedValue()-minAddress
        insn.ops[i] = op
    
    return insn
