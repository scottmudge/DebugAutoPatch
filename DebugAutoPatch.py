import idaapi


class DebugAutoPatchPlugin(idaapi.plugin_t):
    flags = 0
    comment = "Plugin for automatic patch injection - no file patching needed!"
    help = "See "