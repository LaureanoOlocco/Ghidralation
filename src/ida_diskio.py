# ida_diskio wrapper (findcrypt)
# @category GCL

"""ida_diskio wrapper"""

import ghidra
import os


def get_user_idadir():
    """return path to IDA directory"""
    idir = ghidra.GhidraApplicationLayout().getExtensionInstallationDirs()
    path_to_version = os.path.join("IDAPro","Python", "7xx")
    path = str(idir[1]) if len(idir) else str(idir[0]) 
    path += path_to_version
    if not os.path.isdir(path):
        os.makedirs(path)
    return path
