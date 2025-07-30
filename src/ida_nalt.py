# ida_nalt wrapper
# @category GCL

import cp

def get_input_file_path():
    return cp.currentProgram.getExecutablePath()

def get_imagebase():
    return cp.currentProgram.getImageBase().getOffset()