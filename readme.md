DebugAutoPatch
=====

Patching system improvement plugin for IDA.

__Current Version__: 0.2

About
=====

Unfortunately the binary patching functionality of IDA Pro is just painful and tedious. These are the primary issues I have with the way patching currently works:

1. Patches made while _NOT_ debugging __do not__ take effect _UNLESS_ the user first _manually_ patches the _actual_ binary file _before_ beginning the debug session.
2. Patches made _DURING_ the debugging session _DO_ take effect during that particular debugging session, but __will not__ persist into subsequent debugging sessions unless the user, again, _manually_ patches the actual binary file before starting another debug session.
3. Reverting patches is incredibly tedious. First the user must ensure to create a backup of the original binary file. Then the user must revert ALL patches by restoring this original file. Then the user must revert the patches they wish to revert, and then apply all the remaining patches to the binary file.
4. If anything happens to the backup of the original binary file or if the user forgets to first create a backup, they must manually revert the patches in a separate hex editor byte by byte, according to the patches stored in the "Patched bytes" screen.

A much more intuitive and graceful way of managing patches would be:

1. Unless the user __actually wants__ to apply the patches _directly_ to the binary file, the patches are only applied to the _memory_ of the debug session.
2. All patches stored in "Patched bytes" are applied to the debugger memory before the application enters primary execution (or at a pre-defined breakpoint -- this is yet to be implemented).
3. Any patches made _during_ the debug session that get added to the "Patched bytes" database will then automatically be applied to subsequent debug sessions.
4. The user can elect to disable the automatic patching, and thus revert all patches without having to modify the binary file. 

This is __exactly__ what this plugin accomplishes. 

Features
=====

* __No need__ to modify any binary files to apply patches! 
* Automatically synchronizes the existing "Patched bytes" database in IDA with any launched debug sessions. 
* All patches stored in the "Patched bytes" database are applied to the debug session memory at "process start", before the main entry point. 
* Debug hooks automatically suspend process, apply patches, and resume process. The process is seamless and automatic to the user.
* No extra breakpoints are added and no existing breakpoints are modified.
* The ability to disable automatic patching (and thus revert the binary to it's "original" state).
    * These options are available in the existing "Edit > Patch program" menu.
    
Example Video
=====
Click to enlarge...

[![Video example of DebugAutoPatch](https://i.imgur.com/LeC61Nl.gif)](https://giant.gfycat.com/TornMiserableCatbird.webm)

Notes
=====

* For whatever reason, if a user applies patches to a file __outside__ of a debug session, these patches disappear when the debug session starts. This behavior can be explained by the fact that the patches are not applied to the debugged process until the actual binary on-disk is modified, but it makes enumerating the list of patched bytes using debug hooks impossible. 
    * By the time the hook is "snagged", any patches that have not been "physically" applied to the binary disappear.
    * To get around this, a background thread monitors the "Patched bytes" database and updates a cached version/buffer of the patched bytes.
    * This secondary buffer/cache is then used to update debugger memory when the process in launched.
* With this plugin, all patches __will re-appear__ in the "Patched bytes" screen, __regardless__ of whether or not they have been "physically" applied to the actual binary.
* Any patches made during the debug session will also persist into future launches.

Installation
=====
Just copy `DebugAutoPatch.py` file to IDA plugins directory.

TODO
=====

* Add the ability to selectively enable/disable particular patches from being applied to debugger memory.
* Add the ability to define patch "groups" (making the primary group the "default" group). 
    * Add the ability to apply the patch "groups" at particular breakpoints rather than at process start.
    * This will be useful for modifying packed or self-mutating binaries.

Author
=====

This plugin was written by Scott Mudge

https://scottmudge.com
