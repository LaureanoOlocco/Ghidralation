
# @category GCL

import cp
from ghidra.program.flatapi import FlatProgramAPI


GN_VISIBLE = 0x1000 

def get_name(ea, flags):
    fcp = FlatProgramAPI(cp.currentProgram)
    listing = cp.currentProgram.getListing()
    minAddress = cp.currentProgram.minAddress.getOffset()
    codeUnit = listing.getCodeUnitAt(fcp.toAddr(minAddress+ea))
    ret = str()
    if codeUnit != None:
        name = codeUnit.getSymbols()
        if len(name):
            ret = str(name[0])
    return ret
