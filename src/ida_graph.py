
# @category GCL
class GraphViewer:
    UI_Hooks_Trampoline = None
    def __init__(self, title="", close_open=False):
        self.title = title
        self.close_open = close_open
    def AddCommand(self,title, shortcut):
        pass
    def AddEdge(self, src_node, dest_node):
        pass
    def AddNode(self, obj):
        pass
    def Clear(self):
        pass
    def Close(self):
        pass
    def Count(self):
        pass
    def OnCommand(self, cmd_id):
        pass
    def OnPopup(self, widget, popup_handle):
        pass
    def OnRefresh(self):
        pass
    def Select(self, node_id):
        pass
    def Show(self):
        pass
