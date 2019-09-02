# DebugAutoPatch IDA Plugin - UNDER DEVELOPMENT
# Additional support powered by Keystone Engine (http://www.keystone-engine.org).
# By Scott Mudge, 2019 -- https://scottmudge.com.
#
# NOTE: This has been tested with IDA 7.0 - I have made attempts at backward/forward compatibility,
# but please report bugs for other versions.
#
# DebugAutoPatch is released under the GNU GPLv3 license. See LICENSE for more information.
# Find information and latest version at https://github.com/scottmudge/DebugAutoPatch
#
# TBI = To-be-implemented
#
# This IDA plugin automatically applies byte patches stored in the NON-debug IDA "Patched bytes" database
# to the debugged process at runtime. It does this at (by default) the entry-point of the application (or DLL),
# or at a defined breakpoint (TBI). The process will then automatically resume with the patched bytes set in memory.
# (TBI) Patches can also be classified into groups, which can be applied at the group's pre-defined breakpoints (useful
# for packed binaries). Furthermore, patches can be applied arbitrarily at any point during the debug session.
#
# Why? Making modifications to application/rdata code can be tedious, IDA in particular. First the patches must be
# made with the clunky patching tools, and then the binary must be patched on-disk, followed by re-executing the
# application. Compared to features in x64dbg, this is just ridiculously tedious. Furthermore, patching the actual
# binary introduces a number of potential issues which could be mitigated by leaving it untouched. For instance, if
# the module or application performs hash checks to ensure it has not been modified.
#
# Settings and tools can be found in the standard "Edit > Patched bytes" menu. Context/right-click menus can also
# be enabled in the settings dialog.
#
# (TBI) NOTICE:
#   If you wish to use the new patching tool, it will require use of the Keystone engine. Please install
#   using the instructions found here: (http://www.keystone-engine.org).
#
# Developer Notes:
# --------------------
# Change Log:
#   * Just see the commit logs.
#
# TODO:
#   * Add options to set custom patched-application breakpoint, and also option to disable automatic process resumption.
#
#

from threading import Thread, Lock, Event
import logging
import idaapi
import os
import idc
import json


# TEMPORARY!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# ENABLE_DEBUGGING = False
# if ENABLE_DEBUGGING:
#     import pydevd
#     pydevd_pycharm.settrace('localhost', port=12345, stdoutToServer=True, stderrToServer=True)
# /TEMPORARY!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

#  ----------------------------------------- Globals -----------------------------------------
DAP_VERSION = "0.2"
DAP_NAME = "DebugAutoPatch"
DAP_CONFIG_FILE_PATH = os.path.join(idc.GetIdaDirectory(), 'cfg', 'DebugAutoPatch.cfg')
DAP_WEBSITE = "https://github.com/scottmudge/DebugAutoPatch"
DEBUG_MESSAGE_LEVEL = logging.INFO
DAP_INITIALIZED = False
DAP_INSTANCE = None
#  ---------------------------------------------------------------------------------------------


#  ----------------------------------------- Utilities -----------------------------------------
def dap_msg(string):
    print("[{}]: {}".format(DAP_NAME, string))


def dap_warn(string, details = None):
    if details:
        print("[{} | WARNING]: {}\n\t> Details: {}".format(DAP_NAME, string, details))
    else:
        print("[{} | WARNING]: {}".format(DAP_NAME, string))


def dap_err(string, details = None):
    if details:
        print("[{} | ERROR]: {}\n\t> Details: {}".format(DAP_NAME, string, details))
    else:
        print("[{} | ERROR]: {}".format(DAP_NAME, string))


class KillableThread(Thread):
    """Wraps a killable thread that loops at a preset interval. Runs supplied
    target function.
    """
    def __del__(self):
        self.kill()

    def __init__(self, name, target, sleep_interval):
        """
        Args:
            name: Name of the thread, used for logging.
            target (function): Target function
            sleep_interval (float): Sleep interval seconds between loops.
        """
        super(KillableThread, self).__init__(group=None, target=target, name=name)
        self._trigger = Event()
        self._interval = sleep_interval
        self._target = target
        self._name = name
        self._kill = False
        self.setDaemon(True)

    def trigger(self):
        """Triggers loop, but does not kill it."""
        self._kill = False
        self._trigger.set()

    def run(self):
        """Runs the thread."""
        while True:
            try:
                self._target()
                # If no kill signal is set, sleep for the interval,
                # If kill signal comes in while sleeping, immediately
                #  wake up and handle
                is_triggerer = self._trigger.wait(timeout=self._interval)
                if is_triggerer:
                    if self._kill:
                        break
                    else:
                        self._trigger.clear()
            except(KeyboardInterrupt, SystemExit):
                self.kill()
                continue
        dap_msg("Thread killed! [name={}]".format(self._name))

    def kill(self):
        """Kills the thread."""
        dap_msg("Killing thread... [name={}]".format(self._name))
        self._kill = True
        self._trigger.set()
#  ---------------------------------------------------------------------------------------------


class DapCfg:
    def __init__(self):
        pass

    Enabled = "enabled"
    PrimaryPatchAddr = "primary_patch_addr"


# About form
class DAPAboutForm(idaapi.Form):
    def __init__(self):
        # create About form
        super(DAPAboutForm, self).__init__(
            r"""STARTITEM 0
BUTTON YES* Open DebugAutoPatch Website
DebugAutoPatch - About

           {FormChangeCb}
           DebugAutoPatch IDA plugin v%s.
           (c) Scott Mudge, 2019.

           DebugAutoPatch is released under the GPL v3.
           Find more info at %s
           """ % (DAP_VERSION, DAP_WEBSITE), {
                'FormChangeCb': self.FormChangeCb(self.OnFormChange),
            })

        self.Compile()

    # callback to be executed when any form control changed
    @staticmethod
    def OnFormChange(fid):
        if fid == -2:  # Goto homepage
            import webbrowser
            # open Keypatch homepage in a new tab, if possible
            webbrowser.open(DAP_WEBSITE, new=2)

        return 1


# Create menu handlers for IDA >= 700
try:
    # noinspection PyBroadException
    class DapMenuContext(idaapi.action_handler_t):
        label = None

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


    class DapMCEnable(DapMenuContext):
        def activate(self, ctx):
            self.plugin.enable_patching()
            return 1


    class DapMCDisable(DapMenuContext):
        def activate(self, ctx):
            self.plugin.disable_patching()
            return 1


    class DapMCCheckUpdate(DapMenuContext):
        def activate(self, ctx):
            self.plugin.check_update()
            return 1


    class DapMCAbout(DapMenuContext):
        def activate(self, ctx):
            self.plugin.about()
            return 1


    class DapMCApplyPatch(DapMenuContext):
        def activate(self, ctx):
            self.plugin.apply_patch_to_memory()
            return 1


    class DapMCApplyPatchesToProc(DapMenuContext):
        def activate(self, ctx):
            self.plugin.apply_patches_to_current_proc()
            return 1


    class DapMCNull(DapMenuContext):
        def activate(self, ctx):
            self.plugin.menu_null()
            return 1


    class DapMCNull2(DapMenuContext):
        def activate(self, ctx):
            self.plugin.menu_null()
            return 1
except:
    pass


# noinspection PyBroadException
class DebugAutoPatchPlugin(idaapi.plugin_t):
    # This keeps the plugin in memory, important for hooking callbacks
    flags = idaapi.PLUGIN_KEEP
    comment = "Plugin for automatic patched injection - no file patching needed!"
    help = "See https://github.com/scottmudge/IDA_DebugAutoPatch/blob/master/readme.md"
    wanted_name = "DebugAutoPatch"
    wanted_hotkey = ""

    def __del__(self):
        self.term()

    def __init__(self):
        self.old_ida = False
        self.cfg = None
        self.debug_hook = None
        self.patched_bytes_db = []
        self.patched_bytes_db_lock = Lock()
        self.monitor_thread = None

    class PatchedByte:
        """Container for patched byte type."""
        def __init__(self, addr, orig, patched):
            self.addr = addr
            self.orig = orig
            self.patched = patched

    class PatchVisitor(object):
        """Used for visiting patched bytes when debugger is not active. These patches are then stored in a buffer,
        and are applied when debugger activates."""
        def __init__(self):
            self.skipped = 0
            self.patched = 0
            self.patched_bytes = []

        def __call__(self, ea, fpos, orig, patch_val, cnt=()):
            try:
                if fpos == -1:
                    self.skipped += 1
                    dap_msg("fpos invalid ({}) -- patch skipped".format(fpos))
                else:
                    self.patched += 1
                    # dap_msg(" ea: %x \\ fpos: %x \\ o: %x \\ v: %x" % (ea, fpos, orig, patch_val))
                    self.patched_bytes.append(DebugAutoPatchPlugin.PatchedByte(ea, orig, patch_val))
                return 0
            except:
                return

    class DebugHook(idaapi.DBG_Hooks):
        def __init__(self, *args):
            super(DebugAutoPatchPlugin.DebugHook, self).__init__(*args)
            self.steps = 0
            dap_msg("DebugHook INIT")

        def dbg_process_start(self, pid, tid, ea, name, base, size):
            dap_msg("Process start hook snagged -- applying patches...")
            result = DAP_INSTANCE.apply_patches_to_current_proc()
            if result >= 0:
                dap_msg("Success!")

        def dbg_process_exit(self, pid, tid, ea, code):
            dap_msg("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))

        def dbg_library_unload(self, pid, tid, ea, info):
            # dap_msg("Library unloaded: pid=%d tid=%d ea=0x%x info=%s" % (pid, tid, ea, info))
            return 0

        def dbg_process_attach(self, pid, tid, ea, name, base, size):
            dap_msg("Process attach pid=%d tid=%d ea=0x%x name=%s base=%x size=%x" % (pid, tid, ea, name, base, size))

        def dbg_process_detach(self, pid, tid, ea):
            # dap_msg("Process detached, pid=%d tid=%d ea=0x%x" % (pid, tid, ea))
            return 0

        def dbg_library_load(self, pid, tid, ea, name, base, size):
            # dap_msg("Library loaded: pid=%d tid=%d name=%s base=%x" % (pid, tid, name, base))
            pass

        def dbg_bpt(self, tid, ea):
            # dap_msg("Break point at 0x%x pid=%d" % (ea, tid))
            # return values:
            #   -1 - to display a breakpoint warning dialog
            #        if the process is suspended.
            #    0 - to never display a breakpoint warning dialog.
            #    1 - to always display a breakpoint warning dialog.
            return 0

        def dbg_suspend_process(self):
            dap_msg("Process suspended")

        def dbg_exception(self, pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info):
            # dap_msg("Exception: pid=%d tid=%d ea=0x%x exc_code=0x%x can_continue=%d exc_ea=0x%x exc_info=%s" % (
            #   pid, tid, ea, exc_code & idaapi.BADADDR, exc_can_cont, exc_ea, exc_info))
            # return values:
            #   -1 - to display an exception warning dialog
            #        if the process is suspended.
            #   0  - to never display an exception warning dialog.
            #   1  - to always display an exception warning dialog.
            return 0

        def dbg_trace(self, tid, ea):
            # dap_msg("Trace tid=%d ea=0x%x" % (tid, ea))
            # return values:
            #   1  - do not log this trace event;
            #   0  - log it
            return 0

        def dbg_step_into(self):
            self.steps += 1
            # dap_msg("Step into - steps = {}".format(self.steps))
            idaapi.step_into()

        def dbg_run_to(self, pid, tid=0, ea=0):
            # dap_msg("Runto: tid=%d" % tid)
            idaapi.continue_process()

        def dbg_step_over(self):
            self.steps += 1
            # dap_msg("Step over - steps = {}".format(self.steps))
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
        """Initialization routine."""
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

        self.cfg = None

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
            print("DebugAutoPatch v{0} Copyright (c) Scott Mudge 2019".format(DAP_VERSION))
            print("DebugAutoPatch is available from menu Edit | Patch program | ...")
            print("Find more information about DebugAutoPatch at the project github repository")

            self.load_configuration()
            self.set_debug_hooks()

            # Update patch database first
            self.patch_monitor_func()

            dap_msg("Starting patch monitoring thread...")
            self.monitor_thread = KillableThread(name="PatchMonitoring", target=self.patch_monitor_func,
                                                 sleep_interval=1.0)
            self.monitor_thread.start()

            print("=" * 80)
        return idaapi.PLUGIN_KEEP

    def patch_monitor_func(self):
        """Monitors patches and caches patch DB, since IDA has separate DBs for debugged processes and non-debugged
        processes."""
        # Don't collect patches if debugger is on
        try:
            if idaapi.is_debugger_on() or idaapi.is_debugger_busy():
                return

            if not self.patched_bytes_db_lock.acquire(False):
                return
            else:
                try:
                    was_empty = False
                    if len(self.patched_bytes_db) < 1:
                        was_empty = True
                    patches = self.visit_patched_bytes()
                    self.patched_bytes_db = patches
                    if len(patches) > 0 and was_empty:
                        dap_msg("Byte patch buffer populated!")
                finally:
                    self.patched_bytes_db_lock.release()
        except:
            pass

    def enable_patching(self):
        """Enables automatic patching."""
        self.cfg[DapCfg.Enabled] = True
        dap_msg("Automatic patching enabled.")
        pass

    def disable_patching(self):
        """Disables automatic patching."""
        self.cfg[DapCfg.Enabled] = False
        dap_msg("Automatic patching disabled.")
        pass

    def apply_patch_to_memory(self):
        """Adds a new patch to database."""
        # TODO -- Implement
        pass

    def apply_patches_to_current_proc(self):
        """Applies patches to current process. Must first suspend process, check debugger is not active, then
        apply them."""
        if not self.cfg[DapCfg.Enabled]:
            dap_msg("Not applying patches to current process - patching currently disabled.")
            return

        total_applied = 0
        if idaapi.suspend_process():
            self.patched_bytes_db_lock.acquire()
            try:
                if len(self.patched_bytes_db) < 1:
                    dap_msg("No patched bytes currently in database, nothing to do!")
                else:
                    for patch in self.patched_bytes_db:
                        total_applied += self.apply_byte_patch(patch)
                    dap_msg("[{}] total patches applied!".format(total_applied))
            except Exception as e:
                dap_err("Error encountered while applying patches to current debugged process.", str(e))
            except:
                dap_err("Unknown error encountered while applying patches to current debugged process.")
            finally:
                self.patched_bytes_db_lock.release()
        else:
            dap_err("Could not apply patches, could not suspend process!")
        idc.resume_process()
        return total_applied

    @staticmethod
    def about():
        """About window."""
        f = DAPAboutForm()
        f.Execute()
        f.Free()
        pass

    def check_update(self):
        """Checks for new version."""
        # TODO - Update
        pass

    def menu_null(self):
        """For menu item which does nothing."""
        pass

    def run(self, *args):
        """Used for when user selects plugin entry from Edit > Plugins"""
        self.about()
        pass

    def term(self):
        """Termination call."""
        if self.monitor_thread:
            self.monitor_thread.kill()
        self.unset_debug_hooks()
        self.save_configuration()

    def set_debug_hooks(self):
        """Installs debugger hooks for automatic patching."""
        self.unset_debug_hooks()
        dap_msg("Installing debug hooks...")
        self.debug_hook = DebugAutoPatchPlugin.DebugHook()
        self.debug_hook.hook()
        self.debug_hook.steps = 0
        dap_msg("Done!")

    def unset_debug_hooks(self):
        """Remove any installed debug hooks."""
        try:
            if self.debug_hook:
                dap_msg("Removing previously installed debugger hooks...")
                self.debug_hook.unhook()
                dap_msg("Done!")
        except:
            pass

    def apply_byte_patch(self, patched_byte_ojb):
        """Applies a byte patch to current debugger memory."""
        # check if debugger is even running
        if not idaapi.is_debugger_on():
            dap_warn("Cannot apply patched - debugger is not currently on!")
            return
        if not idaapi.is_debugger_busy():
            dap_warn("Cannot apply patched - debugger is not paused!")

        try:
            # patched byte in debugger memory
            if not self.old_ida:
                result = idc.patch_dbg_byte(patched_byte_ojb.addr, patched_byte_ojb.patched)
            else:
                result = idc.PatchDbgByte(patched_byte_ojb.addr, patched_byte_ojb.patched)
            if result > 0:
                idaapi.invalidate_dbgmem_contents(patched_byte_ojb.addr, 1) # addr, size
            return result
        except Exception as e:
            dap_err("Error encountered while applying byte patch to memory!", str(e))
        except:
            dap_err("Unknown error encountered while applying byte patch to memory!")
        return 0

    def visit_patched_bytes(self):
        """Iterates through patched bytes and stores them in a buffer."""
        try:
            visitor = self.PatchVisitor()
            result = idaapi.visit_patched_bytes(0, idaapi.BADADDR, visitor)
            if result != 0:
                dap_err("visit_patched_bytes() returned unexpected result", "error code ({})".format(result))
                return []
            return visitor.patched_bytes
        except Exception as e:
            dap_err("Exception encountered while visiting patched bytes", str(e))
        except:
            dap_err("Unknown")

    def load_configuration(self):
        """Loads configuration from disk."""
        self.cfg = {}
        save_cfg = False
        # load configuration from file
        try:
            f = open(DAP_CONFIG_FILE_PATH, "rt")
            self.cfg = json.load(f)
            f.close()
        except IOError:
            dap_msg("Failed to load config file -- using defaults.")
            save_cfg = True
        except Exception as e:
            dap_err("Failed to load config file.", str(e))

        # Enables or disables patching at debug time
        if DapCfg.Enabled not in self.cfg:
            self.cfg[DapCfg.Enabled] = True
        # Primary patched application address - set to BADADDR = use application start
        if DapCfg.PrimaryPatchAddr not in self.cfg:
            self.cfg[DapCfg.PrimaryPatchAddr] = idaapi.BADADDR
        if save_cfg:
            self.save_configuration()

    def save_configuration(self):
        """Saves configuration to disk."""
        if self.cfg:
            try:
                json.dump(self.cfg, open(DAP_CONFIG_FILE_PATH, "wt"))
            except Exception as e:
                dap_err("Failed to save configuration file", str(e))
            else:
                dap_msg("Saved configuration to: {}".format(DAP_CONFIG_FILE_PATH))


def PLUGIN_ENTRY():
    global DAP_INSTANCE
    logging.basicConfig(format='[%(levelname)s] %(message)s\t(%(module)s:%(funcName)s)')
    logging.root.setLevel(logging.DEBUG)
    # idaapi.notify_when(idaapi.NW_OPENIDB, cache.initialize_cache)
    DAP_INSTANCE = DebugAutoPatchPlugin()
    return DAP_INSTANCE
