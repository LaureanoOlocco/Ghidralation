# ida_diskio wrapper
# @category GCL

"""ida_diskio wrapper"""

import ghidra
import os


def get_user_idadir():
    """Return path to user IDA directory"""
    # Extension directory indices (ordered by priority)
    # [0] = User settings dir/Extensions (highest priority)
    # [1] = Application install dir/Extensions or Development mode dir
    USER_EXTENSIONS_INDEX = 0
    SYSTEM_EXTENSIONS_INDEX = 1

    # Get Ghidra extension installation directories (prioritized list)
    # GhidraApplicationLayout() constructs layout object with app properties and directories
    ghidra_extension_dirs = (
        ghidra.GhidraApplicationLayout().getExtensionInstallationDirs()
    )
    # Define IDA Pro directory structure simulation
    path_to_version = os.path.join("IDAPro", "Python", "7xx")
    # Prefer system extensions directory if available, otherwise use user extensions
    path = (
        str(ghidra_extension_dirs[SYSTEM_EXTENSIONS_INDEX])
        if len(ghidra_extension_dirs) > 1
        else str(ghidra_extension_dirs[USER_EXTENSIONS_INDEX])
    )
    # Combine base path with IDA directory structure
    path = os.path.join(path, path_to_version)
    # Ensure directory exists (create if necessary)
    os.makedirs(path, exist_ok=True)
    return path
