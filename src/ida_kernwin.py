# ida_kernwin wrapper
# @category GCL

def ask_form(*args):
    pass

def ask_str(*args):
    defval = ""
    histId = ""
    prompt = ""
    if len(args)>0:
        defval = args[0]
    if len(args)>1:
        histId = args[1]
    if len(args)>2:
        prompt = args[2]
    return 1

class action_handler_t:

    def __init__(self, *args):
        pass

class action_desc_t:

    def __init__(self, *args):
        pass


def attach_dynamic_action_to_popup(*args):
    pass