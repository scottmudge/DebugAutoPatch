import logging
import idaapi
import os
import idc
import json

VERSION = "0.1"
DBGAP_NAME = "DebugAutoPatch"
DBGAP_CONFIG_FILE_PATH = os.path.join(idc.GetIdaDirectory(), 'cfg', 'DebugAutoPatch.cfg')
DEBUG_MESSAGE_LEVEL = logging.INFO


def dap_msg(string):
    print("{}: {}".format(DBGAP_NAME, string))

def dap_err(string, error):
    print("{}: [ERROR] {}\n\t> Details: {}".format(DBGAP_NAME, string, error))

class DebugAutoPatchPlugin(idaapi.plugin_t):
    # This keeps the plugin in memory, important for hooking callbacks
    flags = idaapi.PLUGIN_KEEP
    comment = "Plugin for automatic patch injection - no file patching needed!"
    help = "See https://github.com/scottmudge/IDA_DebugAutoPatch/blob/master/readme.md"
    wanted_name = "DebugAutoPatch"
    wanted_hotkey = ""

    def init(self):
        global dap_initialized

        self.opts = None

    def run(self):
        pass

    def term(self):
        pass

    def load_configuration(self):
        self.opts = {}

        # load configuration from file
        try:
            f = open(DBGAP_CONFIG_FILE_PATH, "rt")
            self.opts = json.load(f)
            f.close()
        except IOError:
            dap_msg("Failed to load config file -- using defaults.")
        except Exception as e:
            dap_err("Failed to load config file.", str(e))

        # Enables or disables patching at debug time
        if 'enabled' not in self.opts:
            self.opts['enabled'] = True
        # Enables applying patches immediately, when they are set.
        if 'patch_immediately' not in self.opts:
            self.opts['patch_immediately'] = True


def PLUGIN_ENTRY():
    logging.basicConfig(format='[%(levelname)s] %(message)s\t(%(module)s:%(funcName)s)')
    logging.root.setLevel(logging.DEBUG)
    #idaapi.notify_when(idaapi.NW_OPENIDB, cache.initialize_cache)
    return DebugAutoPatchPlugin()


