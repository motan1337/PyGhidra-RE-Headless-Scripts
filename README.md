Analysis Scripts For Ghidra 12.1.2 with PyGhidra headless, origanally all of those were reverse engineering malware and all sorts of software including game cheats,
now i want to release to the public some of my custom scripts, most of them are designed for headless system as i work mostly on vps or headless vms and those make my life easier
and also make the work faster. Of course to be used for your purposes you need to make changes accordingly to your needs and workflows. 

NOT RECOMMENDED FOR SKIDDES xP YOU NEED TO KNOW ALREADY WHAT YOU ARE DOING AND KNOW BASIC PYTHON TO EVEN USE WHAT I EVEN DONE, THOSE ARE NOT PURE RUNNABLE SCRIPTS, MODIFICATIONS ARE NEEDED ! Those are for people who already know Ghidra, PyGhidra and Python and can't be bother to write something from zero, or PoC / personal portofolio.

build_source.py is a module splitter and organizes decompilations into multiple source files.
analyze_modules.py is a cross refrence and string analysis for funtinos with string refs
run_payload_v2.py is a ghidra headless decompilation with 12gb jvm heap, and around 40 min of runtime
run_define_strings_and_redecompile.py is a string annotation for typed strings and redecompilation
annotate_chunks.py adds string context annotations to address range code files
find_features_by_hash.py is FNV-1a hash search for feature variable names
