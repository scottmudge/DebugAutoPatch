import logging
import idaapi
import ida_dbg
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

    class DapMCAbout(Dap_Menu_Context):
        def activate(self, ctx):
            self.plugin.about()
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

    class DapMCNull2(Dap_Menu_Context):
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

    def __init__(self):
        self.old_ida = False
        self.opts = None
        self.debug_hook = None

    class PatchedByte:
        def __init__(self, addr, orig, patched):
            self.addr = addr
            self.orig = orig
            self.patched = patched

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

    class DebugHook(idaapi.DBG_Hooks):
        def __init__(self, *args):
            super(DebugAutoPatchPlugin.DebugHook, self).__init__(*args)
            self.steps = 0

        def dbg_process_start(self, pid, tid, ea, name, base, size):
            dap_msg("Process started, pid=%d tid=%d name=%s" % (pid, tid, name))

        def dbg_process_exit(self, pid, tid, ea, code):
            dap_msg("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))

        def dbg_library_unload(self, pid, tid, ea, info):
            dap_msg("Library unloaded: pid=%d tid=%d ea=0x%x info=%s" % (pid, tid, ea, info))
            return 0

        def dbg_process_attach(self, pid, tid, ea, name, base, size):
            dap_msg("Process attach pid=%d tid=%d ea=0x%x name=%s base=%x size=%x" % (pid, tid, ea, name, base, size))

        def dbg_process_detach(self, pid, tid, ea):
            dap_msg("Process detached, pid=%d tid=%d ea=0x%x" % (pid, tid, ea))
            return 0

        def dbg_library_load(self, pid, tid, ea, name, base, size):
            dap_msg("Library loaded: pid=%d tid=%d name=%s base=%x" % (pid, tid, name, base))

        def dbg_bpt(self, tid, ea):
            dap_msg("Break point at 0x%x pid=%d" % (ea, tid))
            # return values:
            #   -1 - to display a breakpoint warning dialog
            #        if the process is suspended.
            #    0 - to never display a breakpoint warning dialog.
            #    1 - to always display a breakpoint warning dialog.
            return 0

        def dbg_suspend_process(self):
            dap_msg("Process suspended")

        def dbg_exception(self, pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info):
            dap_msg("Exception: pid=%d tid=%d ea=0x%x exc_code=0x%x can_continue=%d exc_ea=0x%x exc_info=%s" % (
                pid, tid, ea, exc_code & idaapi.BADADDR, exc_can_cont, exc_ea, exc_info))
            # return values:
            #   -1 - to display an exception warning dialog
            #        if the process is suspended.
            #   0  - to never display an exception warning dialog.
            #   1  - to always display an exception warning dialog.
            return 0

        def dbg_trace(self, tid, ea):
            dap_msg("Trace tid=%d ea=0x%x" % (tid, ea))
            # return values:
            #   1  - do not log this trace event;
            #   0  - log it
            return 0

        def dbg_step_into(self):
            self.steps += 1
            dap_msg("Step into - steps = {}".format(self.steps))
            idaapi.step_into()

        def dbg_run_to(self, pid, tid=0, ea=0):
            dap_msg("Runto: tid=%d" % tid)
            idaapi.continue_process()

        def dbg_step_over(self):
            self.steps += 1
            dap_msg("Step over - steps = {}".format(self.steps))
            idaapi.step_over()
            # eip = idc.GetRegValue("EIP")
            # dap_msg("0x%x %s" % (eip, idc.GetDisasm(eip)))
            #
            # self.steps += 1
            # if self.steps >= 5:
            #     idaapi.request_exit_process()
            # else:
            #     idaapi.request_step_over()

    def init(self):
        global DAP_INITIALIZED

        if idaapi.IDA_SDK_VERSION < 700:
            self.old_ida = True

        # register menu handlers
        try:
            DapMCNull.register(self, "_________________________")
            DapMCNull2.register(self, "_________________________")
            DapMCEnable.register(self, "Enable Auto-Patching")
            DapMCDisable.register(self, "Disable Auto-Patching")
            DapMCApplyPatch.register(self, "Apply Patch to Memory")
            DapMCApplyPatchesToProc.register(self, "Apply Patches to Current Process")
            DapMCCheckUpdate.register(self, "Check for DebugAutoPatch Update")
            DapMCAbout.register(self, "About DebugAutoPatch")
        except:
            pass

        self.opts = None

        if not DAP_INITIALIZED:
            DAP_INITIALIZED = True

            if not self.old_ida:
                # Add menu IDA >= 7.0
                idaapi.attach_action_to_menu("Edit/Patch program/Null Menu", DapMCNull.get_name(), idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Patch program/Enable Auto-Patching", DapMCEnable.get_name(),
                                             idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Patch program/Disable Auto-Patching", DapMCDisable.get_name(),
                                             idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Patch program/Apply Patch to Memory", DapMCApplyPatch.get_name(),
                                             idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Patch program/Apply Patches to Current Process",
                                             DapMCApplyPatchesToProc.get_name(), idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Patch program/Null Menu 2", DapMCNull2.get_name(),
                                             idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Patch program/Check for DebugAutoPatch Update",
                                             DapMCCheckUpdate.get_name(), idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Patch program/About DebugAutoPatch",
                                             DapMCAbout.get_name(), idaapi.SETMENU_APP)
            else:
                # Older versions
               idaapi.add_menu_item("Edit/Patch program/", "-", "", 1, self.menu_null, None)
               idaapi.add_menu_item("Edit/Patch program/", "Enable Auto-Patching", "", 1,
                                            self.enable_patching, None)
               idaapi.add_menu_item("Edit/Patch program/", "Disable Auto-Patching", "", 1,
                                            self.disable_patching, None)
               idaapi.add_menu_item("Edit/Patch program/", "Apply Patch to Memory", "", 1,
                                            self.apply_patch_to_memory, None)
               idaapi.add_menu_item("Edit/Patch program/", "Apply Patches to Current Process", "", 1,
                                            self.apply_patches_to_current_proc, None)
               idaapi.add_menu_item("Edit/Patch program/", "-", "", 1, self.menu_null, None)
               idaapi.add_menu_item("Edit/Patch program/", "Check for DebugAutoPatch Update", "", 1,
                                            self.check_update, None)
               idaapi.add_menu_item("Edit/Patch program/", "About DebugAutoPatch", "", 1, self.about, None)

            print("=" * 80)
            print("DebugAutoPatch v{0} (c) Scott Mudge, 2019".format(VERSION))
            print("DebugAutoPatch is available from menu Edit | Patch program | ...")
            print("Find more information about DebugAutoPatch at the project github repository")

            self.load_configuration()
            self.set_debug_hooks()

            print("=" * 80)
        return idaapi.PLUGIN_KEEP

    def enable_patching(self):
        pass

    def disable_patching(self):
        pass

    def apply_patch_to_memory(self):
        self.visit_patched_bytes()
        pass

    def apply_patches_to_current_proc(self):
        pass

    def about(self):
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

    def set_debug_hooks(self):
        dap_msg("Installing debug hooks...")
        # Remove previous hook
        try:
            if self.debug_hook:
                dap_msg("Removing previous debug hook")
                self.debug_hook.unhook()
        except:
            pass

        self.debug_hook = DebugAutoPatchPlugin.DebugHook()
        self.debug_hook.hook()
        self.debug_hook.steps = 0
        dap_msg("Done!")

    def apply_byte_patch(self, patched_byte_ojb):
        # check if debugger is even running
        if not idaapi.is_debugger_on():
            dap_err("Cannot apply patch", "debugger is not currently on")
            return
        if not idaapi.is_debugger_busy():
            dap_err("Cannot apply patch", "debugger is not paused")

        # patch byte in debugger memory
        if not self.old_ida:
            idc.patch_dbg_byte(patched_byte_ojb.addr, patched_byte_ojb.patched)
            idaapi.invalidate_dbgmem_contents(patched_byte_ojb.addr, 1)
        else:
            idc.PatchDbgByte(patched_byte_ojb.addr, patched_byte_ojb.patched)
            idaapi.invalidate_dbgmem_contents(patched_byte_ojb.addr, 1)

    def visit_patched_bytes(self):
        visitor = self.PatchVisitor()
        result = idaapi.visit_patched_bytes(0, idaapi.BADADDR, visitor)
        if result != 0:
            dap_err("visit_patched_bytes() returned unexpected result", "error code ({})".format(result))
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


