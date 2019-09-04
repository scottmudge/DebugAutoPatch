# DebugAutoPatch IDA Plugin
# Patching improvement plugin for IDA v7.0+
#
# Additional support powered by Keystone Engine (http://www.keystone-engine.org).
# By Scott Mudge, 2019 -- https://scottmudge.com.
#
# NOTE: This has been tested with IDA 7.0 - I have made attempts at backward/forward compatibility,
# but please report bugs for other versions.
#
# DebugAutoPatch is released under the GNU GPLv3 license. See LICENSE for more information.
# Find information and latest version at https://github.com/scottmudge/DebugAutoPatch
#
# This IDA plugin automatically applies byte patches stored in the NON-debug IDA "Patched bytes" database
# to the debugged process at runtime. It does this at (by default) the entry-point of the application (or DLL).
# The process will then automatically resume with the patched bytes set in memory.
#
# Why? Making modifications to application/.rdata code can be tedious, IDA in particular. First the patches must be
# made with the clunky patching tools, and then the binary must be patched on-disk, followed by re-executing the
# application. Furthermore, patching the actual binary introduces a number of potential issues which could be
# mitigated by leaving it untouched. For instance, if the module or application performs hash checks to ensure it
# has not been modified.
#
# Developer Notes:
# --------------------
# Change Log:
#   * Just see the commit logs.
#

from threading import Thread, Lock, Event
from idaapi import PluginForm
import cPickle as pickle
import gzip
import logging
import idaapi
import os
import idc
import json

# Qt Imports
from PyQt5 import QtCore, QtGui, QtWidgets
# noinspection PyUnresolvedReferences
from PyQt5.QtWidgets import QMainWindow, QLabel, QGridLayout, QVBoxLayout, QWidget, QDialog, QPushButton
# noinspection PyUnresolvedReferences
from PyQt5.QtCore import QSize, QRect
# noinspection PyUnresolvedReferences
from PyQt5.QtGui import QIcon, QPixmap, QImage

# TEMPORARY!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
ENABLE_DEBUGGING = False
if ENABLE_DEBUGGING:
    import pydevd
    pydevd.settrace('localhost', port=12345, stdoutToServer=True, stderrToServer=True)
# /TEMPORARY!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

#  ----------------------------------------- Globals -----------------------------------------
DAP_VERSION = "0.2"
DAP_NAME = "DebugAutoPatch"
DAP_CONFIG_FILE_PATH = os.path.join(idc.GetIdaDirectory(), 'cfg', 'DebugAutoPatch.cfg')
DAP_WEBSITE = "https://github.com/scottmudge/DebugAutoPatch"
DEBUG_MESSAGE_LEVEL = logging.INFO
DAP_INITIALIZED = False
DAP_INSTANCE = None
DAP_DB_COOKIE = 0xDA9DB003

DAP_ICON_B64 = "iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAyZpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuNi1jMTQ1IDc5LjE2MzQ5OSwgMjAxOC8wOC8xMy0xNjo0MDoyMiAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RSZWY9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZVJlZiMiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENDIDIwMTkgKFdpbmRvd3MpIiB4bXBNTTpJbnN0YW5jZUlEPSJ4bXAuaWlkOjVCRjU0RjBEQ0U1RTExRTlBOTI2RDc0NjI1NjY2MzgyIiB4bXBNTTpEb2N1bWVudElEPSJ4bXAuZGlkOjVCRjU0RjBFQ0U1RTExRTlBOTI2RDc0NjI1NjY2MzgyIj4gPHhtcE1NOkRlcml2ZWRGcm9tIHN0UmVmOmluc3RhbmNlSUQ9InhtcC5paWQ6NUJGNTRGMEJDRTVFMTFFOUE5MjZENzQ2MjU2NjYzODIiIHN0UmVmOmRvY3VtZW50SUQ9InhtcC5kaWQ6NUJGNTRGMENDRTVFMTFFOUE5MjZENzQ2MjU2NjYzODIiLz4gPC9yZGY6RGVzY3JpcHRpb24+IDwvcmRmOlJERj4gPC94OnhtcG1ldGE+IDw/eHBhY2tldCBlbmQ9InIiPz5hS5TrAABODklEQVR42uxd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"
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


def get_filename_without_ext(filename):
    """Returns filename without the extension"""
    return os.path.splitext(filename)[0]


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


#  ------------------------------------- User Interface --------------------------------------
class TestPluginForm(PluginForm):
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        layout = QtWidgets.QVBoxLayout()

        layout.addWidget(
            QtWidgets.QLabel("This is a test <font color=green>this is green</font>.")
        )

        layout.addWidget(
            QtWidgets.QLabel("This is a second test line.")
        )

        self.parent.setLayout(layout)

    def OnClose(self, form):
        pass


class AboutWindow(QDialog):
    def __init__(self):
        self._show_thread = None
        QMainWindow.__init__(self)

        self.setMinimumSize(QSize(300, 150))
        self.setMaximumSize(QSize(300, 150))
        self.setWindowTitle("DebugAutoPatch - About")
        self.setWindowModality(QtCore.Qt.ApplicationModal)

        button = QPushButton("Close", self)
        button.clicked.connect(self.close)
        button.move(160 - (0.5 * button.width()), 150 - button.height())

        img_bytes = QtCore.QByteArray.fromBase64(DAP_ICON_B64)
        image = QImage()
        image.loadFromData(img_bytes, "PNG")
        pixmap = QPixmap.fromImage(image)
        label_img = QLabel(self)
        label_img.setPixmap(pixmap.scaled(64, 64, QtCore.Qt.KeepAspectRatio))
        label_img.move(10, 10)

        label_main = QLabel("DebugAutoPatch - Version {}".format(DAP_VERSION), self)
        label_main.move(84, 16)
        label_subtitle = QLabel("Patching improvement plugin for IDA", self)
        label_subtitle.move(90, 32)
        label_author = QLabel("Copyright (c) 2019 - Scott Mudge", self)
        label_author.move(84, 48)
        label_link = QLabel("https://github.com/scottmudge/DebugAutoPatch", self)
        label_link.move(14, 84)
        label_license = QLabel("Licensed under GPLv3", self)
        label_license.move(14, 100)

        self.setWindowIcon(QIcon(pixmap))

    def show(self):
        self.exec_()
# ---------------------------------------------------------------------------------------------


class DapCfg:
    def __init__(self):
        pass

    Enabled = "enabled"
    PrimaryPatchAddr = "primary_patch_addr"


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


class PatchedBytes:
    """Container for patched byte type."""

    def __init__(self, addr, orig, patched):
        self.addr = addr

        if len(orig) != len(patched):
            dap_err("Error creating PatchedBytes object - len(orig) != len(patched).")

        self.orig = orig
        self.patched = patched


class PatchGroup:
    """Container for patch group."""

    def __init__(self, name, enabled=True):
        self.patches = []
        self.name = name
        self.enabled = enabled


class GroupDatabase:
    """Container for group database. Contains cookie to ensure serialized data is fine and version checking."""
    def __init__(self):
        self.cookie = int(DAP_DB_COOKIE)
        self.groups = {}
        self.add_group("default", True)

    def get_group(self, name):
        """Returns group by name."""
        if name not in self.groups:
            dap_warn("Requested group [{}] is not in group database.".format(name))
            return None
        return self.groups[name]

    def add_group(self, name, enabled = True):
        """Adds group to database."""
        self.groups.update({name : PatchGroup(name, enabled)})

    def delete_group(self, name):
        """Deletes group from database."""
        if name in self.groups:
            del self.groups[name]
        else:
            dap_warn("Requested group [{}] not found in group database. Cannot delete.".format(name))


class DebugAutoPatchPlugin(idaapi.plugin_t):
    # This keeps the plugin in memory, important for hooking callbacks
    flags = idaapi.PLUGIN_KEEP
    comment = "Plugin for automatic byte patch injection - no binary-file patching needed!"
    help = "See https://github.com/scottmudge/IDA_DebugAutoPatch/blob/master/readme.md"
    wanted_name = "DebugAutoPatch"
    wanted_hotkey = ""

    class PatchVisitor(object):
        """Used for visiting patched bytes when debugger is not active. These patches are then stored in a buffer,
        and are applied when debugger activates."""
        def __init__(self):
            self.skipped = 0
            self.total_patched = 0
            self.total_bytes = 0
            self.patches = []

            self.last_addr = -2

            self.patch_start_addr = 0
            self.patched_bytes_buf = []
            self.orig_bytes_buf = []

        def __call__(self, ea, fpos, orig, patch_val, cnt=()):
            try:
                if fpos == -1:
                    self.skipped += 1
                    dap_msg("fpos invalid ({}) -- patch skipped".format(fpos))
                else:
                    # Check for same address
                    if self.last_addr == ea:
                        dap_warn("Same address encountered while visiting patches: {}".format(ea))
                        return 0

                    self.total_bytes += 1

                    # If this is a non-contiguous patch
                    if abs(self.last_addr - ea) > 1:
                        self.consolidate()
                        self.patch_start_addr = ea

                    self.patched_bytes_buf.append(patch_val)
                    self.orig_bytes_buf.append(orig)

                    self.last_addr = ea
                return 0
            except:
                return

        def consolidate(self):
            """Consolidates buffers."""
            if len(self.patched_bytes_buf) > 0 and (len(self.patched_bytes_buf) == len(self.orig_bytes_buf)):
                self.patches.append(PatchedBytes(self.patch_start_addr, self.orig_bytes_buf, self.patched_bytes_buf))

            self.patched_bytes_buf = []
            self.orig_bytes_buf = []
            self.patch_start_addr = 0

    class DebugHook(idaapi.DBG_Hooks):
        def __init__(self, *args):
            super(DebugAutoPatchPlugin.DebugHook, self).__init__(*args)
            self.steps = 0

        def dbg_process_start(self, pid, tid, ea, name, base, size):
            dap_msg("Process start hook snagged -- applying patches...")
            result = DAP_INSTANCE.apply_all_patches_to_current_proc()
            if result >= 0:
                dap_msg("Success!")

        # def dbg_process_exit(self, pid, tid, ea, code):
        #     dap_msg("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))
        #
        # def dbg_library_unload(self, pid, tid, ea, info):
        #     # dap_msg("Library unloaded: pid=%d tid=%d ea=0x%x info=%s" % (pid, tid, ea, info))
        #     return 0
        #
        # def dbg_process_attach(self, pid, tid, ea, name, base, size):
        #     dap_msg("Process attach pid=%d tid=%d ea=0x%x name=%s base=%x size=%x" % (pid, tid, ea, name, base, size))
        #
        # def dbg_process_detach(self, pid, tid, ea):
        #     # dap_msg("Process detached, pid=%d tid=%d ea=0x%x" % (pid, tid, ea))
        #     return 0
        #
        # def dbg_library_load(self, pid, tid, ea, name, base, size):
        #     # dap_msg("Library loaded: pid=%d tid=%d name=%s base=%x" % (pid, tid, name, base))
        #     pass
        #
        # def dbg_bpt(self, tid, ea):
        #     # dap_msg("Break point at 0x%x pid=%d" % (ea, tid))
        #     # return values:
        #     #   -1 - to display a breakpoint warning dialog
        #     #        if the process is suspended.
        #     #    0 - to never display a breakpoint warning dialog.
        #     #    1 - to always display a breakpoint warning dialog.
        #     return 0
        #
        # def dbg_suspend_process(self):
        #     dap_msg("Process suspended")
        #
        # def dbg_exception(self, pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info):
        #     # dap_msg("Exception: pid=%d tid=%d ea=0x%x exc_code=0x%x can_continue=%d exc_ea=0x%x exc_info=%s" % (
        #     #   pid, tid, ea, exc_code & idaapi.BADADDR, exc_can_cont, exc_ea, exc_info))
        #     # return values:
        #     #   -1 - to display an exception warning dialog
        #     #        if the process is suspended.
        #     #   0  - to never display an exception warning dialog.
        #     #   1  - to always display an exception warning dialog.
        #     return 0
        #
        # def dbg_trace(self, tid, ea):
        #     # dap_msg("Trace tid=%d ea=0x%x" % (tid, ea))
        #     # return values:
        #     #   1  - do not log this trace event;
        #     #   0  - log it
        #     return 0
        #
        # def dbg_step_into(self):
        #     self.steps += 1
        #     # dap_msg("Step into - steps = {}".format(self.steps))
        #     idaapi.step_into()
        #
        # def dbg_run_to(self, pid, tid=0, ea=0):
        #     # dap_msg("Runto: tid=%d" % tid)
        #     idaapi.continue_process()
        #
        # def dbg_step_over(self):
        #     self.steps += 1
        #     # dap_msg("Step over - steps = {}".format(self.steps))
        #     idaapi.step_over()
        #     # eip = idc.GetRegValue("EIP")
        #     # dap_msg("0x%x %s" % (eip, idc.GetDisasm(eip)))
        #     #
        #     # self.steps += 1
        #     # if self.steps >= 5:
        #     #     idaapi.request_exit_process()
        #     # else:
        #     #     idaapi.request_step_over()

    def __del__(self):
        self.term()

    def __init__(self):
        self.cfg = None
        self.debug_hook = None
        self.patch_db = GroupDatabase()
        self.patch_db_lock = Lock()
        self.patched_bytes_db = []
        self.patched_bytes_db_lock = Lock()
        self.monitor_thread = None
        self.cur_idb_path = ""
        self.patch_db_path = ""

    def initialize_default_db(self):
        """Initializes a default database."""
        self.patch_db_lock.acquire()
        try:
            self.patch_db = GroupDatabase()
        except Exception as e:
            dap_warn("Error initializing default patch group database.", str(e))
        except:
            dap_warn("Unknown error while initializing default patch group database.")
        finally:
            self.patch_db_lock.release()

    def save_database(self):
        """Saves the patch database (.dap file) to disk."""
        if len(self.patch_db_path) < 3:
            return

        # Delete if it exists
        try:
            if os.path.exists(self.patch_db_path):
                os.remove(self.patch_db_path)
            # double check
            if os.path.exists(self.patch_db_path):
                raise IOError("file still exists")
        except:
            dap_err("Could not save patch database, could not delete existing file.")
            return

        # Acquire lock and dump
        self.patch_db_lock.acquire()
        try:
            with gzip.open(self.patch_db_path, 'wb') as db_file:
                pickle.dump(self.patch_db, db_file)
            dap_msg("Saved patch database to: {}".format(self.patch_db_path))
        except Exception as e:
            dap_warn("Error saving patch database.", str(e))
        except:
            dap_warn("Unknown error while saving patch database.")
        finally:
            self.patch_db_lock.release()

    def load_database(self):
        """Loads the patch database (.dap file) from disk."""
        if len(self.patch_db_path) < 3:
            return

        if not os.path.exists(self.patch_db_path):
            dap_msg("No patch database file found. Starting fresh database.")
            return

        if not os.path.isfile(self.patch_db_path):
            dap_warn("Patch database path ({}) is not a file. Cannot load or save database.".format(self.patch_db_path))
            return

        failed = True

        # Acquire lock and load
        self.patch_db_lock.acquire()
        try:
            with gzip.open(self.patch_db_path, 'rb') as db_file:
                self.patch_db = pickle.load(db_file)
            if self.patch_db.cookie != int(DAP_DB_COOKIE):
                raise IOError("Invalid database cookie. File is corrupt or from an incompatible earlier version.")
            dap_msg("Loaded patch database from: {}".format(self.patch_db_path))
            failed = False
        except Exception as e:
            dap_warn("Error loading patch database.", str(e))
        except:
            dap_warn("Unknown error while loading patch database.")
        finally:
            self.patch_db_lock.release()

        # Initialize a new DB if loading failed.
        if failed:
            self.initialize_default_db()

    def init(self):
        """Initialization routine."""
        global DAP_INITIALIZED

        if idaapi.IDA_SDK_VERSION < 700:
            error_dialog = QtWidgets.QErrorMessage()
            error_dialog.showMessage("DebugAutoPatch does NOT support versions of IDA earlier than 7.0!")
            error_dialog.exec_()
            return idaapi.PLUGIN_SKIP

        # Get IDB path and parse to establish DB path
        self.cur_idb_path = idc.get_idb_path()
        self.patch_db_path = get_filename_without_ext(self.cur_idb_path) + ".dap"

        # Initialize default database
        self.initialize_default_db()

        # Load database if it exists
        self.load_database()

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

            print("=" * 80)
            print("DebugAutoPatch v{0} Copyright (c) Scott Mudge 2019".format(DAP_VERSION))
            print("DebugAutoPatch is available from menu \"Edit > Patch program\"")
            print("Find more information about DebugAutoPatch at the project github repository")

            self.load_configuration()
            self.set_debug_hooks()

            # Update patch database first
            self.patch_monitor_func()

            # Save database (if default)
            self.save_database()

            dap_msg("Starting patch monitoring thread...")
            self.monitor_thread = KillableThread(name="PatchMonitoring", target=self.patch_monitor_func,
                                                 sleep_interval=0.7)
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
        pass

    def apply_named_patch_group_to_current_proc(self, patch_group_name):
        """Applies a named patch group to current process."""
        pass

    def apply_patch_group_to_current_proc(self, patch_group):
        """Applies supplied patch group to current process."""
        pass

    def apply_all_patches_to_current_proc(self):
        """Applies ALL patches to current process."""
        if not self.cfg[DapCfg.Enabled]:
            dap_msg("Not applying patches to current process - patching currently disabled.")
            return

        total_applied = 0
        total_bytes_patched = 0
        if idaapi.suspend_process():
            self.patched_bytes_db_lock.acquire()
            try:
                if len(self.patched_bytes_db) < 1:
                    dap_msg("No patched bytes currently in database, nothing to do!")
                else:
                    for patch in self.patched_bytes_db:
                        total_applied += 1
                        total_bytes_patched += self.apply_byte_patch(patch)
                    dap_msg("[{}] total patches applied / [{}] total bytes modified!"
                            .format(total_applied, total_bytes_patched))
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
        window = AboutWindow()
        window.show()
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

    @staticmethod
    def apply_byte_patch(patched_byte_ojb):
        """Applies a byte patch to current debugger memory."""
        # check if debugger is even running
        if not idaapi.is_debugger_on():
            dap_warn("Cannot apply patch - debugger is not currently on!")
            return 0

        num_orig = len(patched_byte_ojb.orig)
        num_patched = len(patched_byte_ojb.patched)
        start_addr = patched_byte_ojb.addr

        total_applied = 0

        if num_orig != num_patched:
            dap_err("Cannot apply patch, length of orig bytes [{}] != length of patched bytes [{}]!"
                    .format(num_orig, num_patched))
            return 0

        for i in range(0, num_patched):
            addr = start_addr + i
            byte = patched_byte_ojb.patched[i]

            try:
                # patched byte in debugger memory
                total_applied += idc.PatchDbgByte(addr, byte)
            except Exception as e:
                dap_err("Error encountered while applying byte patch to memory!", str(e))
            except:
                dap_err("Unknown error encountered while applying byte patch to memory!")

        if total_applied > 0:
            idaapi.invalidate_dbgmem_contents(start_addr, total_applied)  # addr, size

        return total_applied

    def visit_patched_bytes(self):
        """Iterates through patched bytes and stores them in a buffer."""
        try:
            visitor = self.PatchVisitor()
            result = idaapi.visit_patched_bytes(0, idaapi.BADADDR, visitor)
            if result != 0:
                dap_err("visit_patched_bytes() returned unexpected result", "error code ({})".format(result))
                return []
            visitor.consolidate()
            return visitor.patches
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
    DAP_INSTANCE = DebugAutoPatchPlugin()
    return DAP_INSTANCE
