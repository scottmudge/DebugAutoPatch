#Debug Auto Patch
###Plugin for IDA Pro 7.0+

About
=====

This plugin applies binary patches to the currently debugged process both automatically at launch time and when they are
added to the patch database.

Often when IDA users create patches (with either the inbuilt method or with Keypatch), they must terminate the 
application, apply the patched bytes, restart the application, and hope it all worked correctly. This is not always
ideal. Restarting the process may lose precious state variables which could easily be lost of forgotten.

This plugin will both immediately apply the patched bytes when they are set, and will apply them at launch time to the 
debugger memory without needing to actually patch the file itself.

Do note that the patched bytes will be applied at the time they are established (if the debugger is currently stopped),
or when the first breakpoint it set. So it is advisable to set a breakpoint at/near the entry point of the application
you are analyzing/patching.

Installation
=====
Just copy `DebugAutoPatch.py` file and `DebugAutoPatch` directory (if it exists) to Ida plugins directory.

Configuration
=====

To be written.

Features
=====
To be written.

Author
=====

This plugin was written by Scott Mudge.