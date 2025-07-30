# idaapi wrapper
# @category GCL


from os import getcwd, path
import cp as cp
import ida_nalt
import ida_kernwin
from ghidra.program.flatapi import FlatProgramAPI

SN_NOCHECK = 0
BWN_DISASM = 0
AST_ENABLE_FOR_WIDGET = 2
AST_DISABLE_FOR_WIDGET = 3
PLUGIN_KEEP = 2
PLUGIN_UNL = 8
PLUGIN_OK = 1
SETMENU_APP = 1

# uefi re tool
PLUGIN_MOD = 1
PLUGIN_PROC = 64
PLUGIN_FIX = 128
BADADDR = hex(4294967295)

action_desc_t = ida_kernwin.action_desc_t()
get_input_file_path = ida_nalt.get_input_file_path
ask_str = ida_kernwin.ask_str
get_imagebase = ida_nalt.get_imagebase


def action_desc_t(*args):
    return args[0]


class action_handler_t:

    def __init__(self):
        self.__name__ = self.__class__.__name__


class Choose:

    CHCOL_HEX = 0
    CHCOL_PLAIN = 0

    def __init__(self, *args, **kwargs):
        self.title = args[0]
        self.res = dict()
        for item in args[1]:
            self.res[item[0]] = None

    def Show(self):
        """print results of search"""

        for item in self.items:
            for k, v in enumerate(item):
                print(str(list(self.res.keys())[k])+':',v,'| ', end='')
            print()
        return True


class plugin_t:
    """Mock class"""

    def __init__(self):
        self.user_directory = ""


def register_action(*args):
    pass


def unregister_action(*args):
    pass


def attach_action_to_menu(*args):
    pass


def set_name(l_addr, comment, flags=SN_NOCHECK):
    """
    @param l_addr - linear address
    @param name - new name of address. If name == "", then delete old name
    @param flags - combination of SN_... constants
    comment on an address
    """
    fcp = FlatProgramAPI(cp.currentProgram)
    minAddress = cp.currentProgram.minAddress.getOffset()
    if flags == SN_NOCHECK:
        # Precomment
        cp.currentProgram.listing.setComment(fcp.toAddr(l_addr+minAddress), 1, comment)


# currently in ida kernwin
class Form:
    """mock form"""

    def __init__(self, form, controls):
        self.form = form
        self.txtFile = self.txtfile(0, path.join(
            controls["txtFile"], "symbols.elf"))

    class txtfile:
        def __init__(self, id, value):
            self.id = id
            self.value = value

    def GetControlValue(*args):
        pass

    def SetControlValue(file):
        pass

    def FormChangeCb(cfunc):
        pass

    def FileInput(**kwargs):
        return getcwd()

    def Compile(self):
        return True

    def Compiled(self):
        return False

    def Execute(*args):
        return 1

    def Free(self):
        pass


def get_file_type_name():
    """returns the format of an executable file"""
    return str(cp.currentProgram.getExecutableFormat())


def warning(*args):
    pass
