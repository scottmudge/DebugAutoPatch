import logging
import idaapi
import os
import idc
import json

VERSION = "0.1"
DBGAP_NAME = "DebugAutoPatch"
DBGAP_CONFIG_FILE_PATH = os.path.join(idc.GetIdaDirectory(), 'cfg', 'DebugAutoPatch.cfg')
DEBUG_MESSAGE_LEVEL = logging.INFO
DAP_INITIALIZED = False


# Create menu handlers for IDA >= 700
try:
    class Dap_Menu_Context(idaapi.action_handler_t):
        @classmethod
        def get_name(self):
            return self.__name__

        @classmethod
        def get_label(self):
            return self.label

        @classmethod
        def register(self, plugin, label):
            self.plugin = plugin
            self.label = label
            instance = self()
            return idaapi.register_action(idaapi.action_desc_t(
                self.get_name(),  # Name. Acts as an ID. Must be unique.
                instance.get_label(),  # Label. That's what users see.
                instance  # Handler. Called when activated, and for updating
            ))

        @classmethod
        def unregister(self):
            """Unregister the action.
            After unregistering the class cannot be used.
            """
            idaapi.unregister_action(self.get_name())

        @classmethod
        def activate(self, ctx):
            # dummy method
            return 1

        @classmethod
        def update(self, ctx):
            try:
                if ctx.form_type == idaapi.BWN_DISASM:
                    return idaapi.AST_ENABLE_FOR_FORM
                else:
                    return idaapi.AST_DISABLE_FOR_FORM
            except:
                # Add exception for main menu on >= IDA 7.0
                return idaapi.AST_ENABLE_ALWAYS

    class DapMCEnable(Dap_Menu_Context):
        def activate(self, ctx):
            self.plugin.enable_patching()
            return 1

    class DapMCDisable(Dap_Menu_Context):
        def activate(self, ctx):
            self.plugin.disable_patching()
            return 1

    class DapMCCheckUpdate(Dap_Menu_Context):
        def activate(self, ctx):
            self.plugin.check_update()
            return 1

    class DapMCApplyPatch(Dap_Menu_Context):
        def activate(self, ctx):
            self.plugin.apply_patch_to_memory()
            return 1

    class DapMCApplyPatchesToProc(Dap_Menu_Context):
        def activate(self, ctx):
            self.plugin.apply_patches_to_current_proc()
            return 1

    class DapMCNull(Dap_Menu_Context):
        def activate(self, ctx):
            self.plugin.menu_null()
            return 1
except:
    pass


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

    class PatchVisitor(object):
        def __init__(self):
            self.skip = 0
            self.patch = 0

        def __call__(self, ea, fpos, o, v, cnt=()):
            dap_msg("Visiting all patched bytes...")

            if fpos == -1:
                self.skip += 1
                dap_msg(" ea: %x \\ fpos: %x \\ o: %x \\ v: %x... skipped" % (ea, fpos, o, v))
            else:
                self.patch += 1
                dap_msg(" ea: %x \\ fpos: %x \\ o: %x \\ v: %x" % (ea, fpos, o, v))

            dap_msg("Done!")

            return 0

    def init(self):
        global DAP_INITIALIZED

        # register popup menu handlers
        try:
            # TODO -- Finish
            pass
        except:
            pass

        self.opts = None

        if not DAP_INITIALIZED:
            DAP_INITIALIZED = True

            #TODO -- Add Menu Items

            if idaapi.IDA_SDK_VERSION >= 700:
                # Add menu IDA >= 7.0
                idaapi.attach_action_to_menu("Edit/Patch program/-", DapMCNull.get_name(), idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Patch program/Enable Auto-Patching", DapMCEnable.get_name(),
                                             idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Patch program/Disable Auto-Patching", DapMCDisable.get_name(),
                                             idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Patch program/Apply Patch to Memory", DapMCApplyPatch.get_name(),
                                             idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Patch program/Apply Patches to Current Process",
                                             DapMCApplyPatchesToProc.get_name(), idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Patch program/-", DapMCNull.get_name(), idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Patch program/Check for DebugAutoPatch Update",
                                             DapMCCheckUpdate.get_name(), idaapi.SETMENU_APP)
            else:
                # Older versions
                menu = idaapi.add_menu_item("Edit/Patch program/", "-", "", 1, self.menu_null, None)
                menu = idaapi.add_menu_item("Edit/Patch program/", "Enable Auto-Patching", "", 1,
                                            self.enable_patching, None)
                menu = idaapi.add_menu_item("Edit/Patch program/", "Disable Auto-Patching", "", 1,
                                            self.disable_patching, None)
                menu = idaapi.add_menu_item("Edit/Patch program/", "Apply Patch to Memory", "", 1,
                                            self.apply_patch_to_memory, None)
                menu = idaapi.add_menu_item("Edit/Patch program/", "Apply Patches to Current Process", "", 1,
                                            self.apply_patches_to_current_proc, None)
                menu = idaapi.add_menu_item("Edit/Patch program/", "-", "", 1, self.menu_null, None)
                menu = idaapi.add_menu_item("Edit/Patch program/", "Check for DebugAutoPatch Update", "", 1,
                                            self.check_update, None)

        print("=" * 80)
        print("DebugAutoPatch v{0} (c) Scott Mudge, 2019".format(VERSION))
        print("Keypatch Search is available from menu Edit | Patch program | ...")
        print("Find more information about DebugAutoPatch at the project github repository")

        self.load_configuration()

        print("=" * 80)

    def enable_patching(self):
        pass

    def disable_patching(self):
        pass

    def apply_patch_to_memory(self):
        pass

    def apply_patches_to_current_proc(self):
        pass

    def check_update(self):
        pass

    def menu_null(self):
        pass

    def run(self):
        pass

    def about(self):
        pass

    def term(self):
        pass

    def visit_patched_bytes(self):
        visitor = self.PatchVisitor()
        result = idaapi.visit_patched_bytes(0, idaapi.BADADDR, visitor)
        if result != 0:
            dap_err("visit_patched_bytes() returned unexpected result (code {})".format(result))
        else:
            dap_msg("Total Patched Bytes: {}  ...  Total Skipped Bytes: {}".format(visitor.patch, visitor.skip))

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


