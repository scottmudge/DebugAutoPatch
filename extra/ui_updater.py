# Run this while editing the UI file in Qt Designer. It will automatically update the base64-encoded UI in the primary
# plugin file.
#
# Author: Scott Mudge - 2019

import os
import base64
import sys
import fileinput
from time import sleep
import datetime

SOURCE_FILENAME = "DebugAutoPatch.py"
UI_FILENAME = "dap.ui"
CUR_PATH = os.path.dirname(os.path.abspath(__file__))
UI_FILE = "{}/{}".format(CUR_PATH, UI_FILENAME)
SOURCE_FILE = "{}/../{}".format(CUR_PATH, SOURCE_FILENAME)


def get_time_stamp_str():
    """Returns timestamp as string"""
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def update_source_file():
    try:
        with open(UI_FILE, 'r') as ui_file_r:
            ui_content = ui_file_r.read()
            ui_content_b64 = base64.b64encode(ui_content)

        if not ui_content_b64 or len(ui_content_b64) < 16:
            print("Error: Base64 result is too small...")
            return False

        for line in fileinput.input([SOURCE_FILE], inplace=True):
            if line.strip().startswith('DAP_UI_B64 = '):
                line = "DAP_UI_B64 = \"{}\"\n".format(ui_content_b64)
            sys.stdout.write(line)

        print("Successfully updated source file at: {}".format(get_time_stamp_str()))
        return True
    except Exception as e:
        print("Error - Could not update source file: {}".format(str(e)))
    except:
        print("Unknown error - Could not update source file.")
    return False


if __name__ == '__main__':
    try:
        print("UI Updater Started!")
        # Update just to start
        update_source_file()
        start_ts = os.stat(UI_FILE).st_mtime

        while True:
            new_ts = os.stat(UI_FILE).st_mtime
            if new_ts != start_ts:
                update_source_file()
                start_ts = new_ts

            sleep(0.750)
            continue
    except(KeyboardInterrupt, SystemExit):
        print("UI Updater Terminated...")
        sys.exit(0)
    except IOError:
        pass