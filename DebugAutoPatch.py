import logging
import idaapi
import DebugAutoPatch.settings as settings


class DebugAutoPatchPlugin(idaapi.plugin_t):
    flags = 0
    comment = "Plugin for automatic patch injection - no file patching needed!"
    help = "See https://github.com/scottmudge/IDA_DebugAutoPatch/blob/master/readme.md"
    wanted_name = "DebugAutoPatch"
    wanted_hotkey = ""

    @staticmethod
    def init():
        pass

    @staticmethod
    def run():
        pass

    @staticmethod
    def term():
        pass


def PLUGIN_ENTRY():
    settings.load_settings()
    logging.basicConfig(format='[%(levelname)s] %(message)s\t(%(module)s:%(funcName)s)')
    logging.root.setLevel(logging.DEBUG)
    #idaapi.notify_when(idaapi.NW_OPENIDB, cache.initialize_cache)
    return DebugAutoPatchPlugin()


