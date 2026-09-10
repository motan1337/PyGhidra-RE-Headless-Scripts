import os
import sys
import re
import gc
import shutil

GHIDRA_INSTALL = r"C:\Users\user\Documents\docs\docs\docs\ghidra_12.1.2_PUBLIC"
OUT_DIR = r"C:\Users\user\Documents\docs\docs\docs\ghidra_output"
PROJECT_DIR = r"C:\Users\user\Documents\docs\docs\docs\ghidra_projects"
PAYLOAD_PATH = r"C:\Users\user\Documents\docs\docs\docs\memdump\CHEAT_FULL_DUMP.bin"
STRINGS_FILE = r"C:\Users\user\Documents\docs\docs\docs\memdump\CHEAT_STRINGS.txt"
PROJECT_NAME = "Payload_Strings"

os.makedirs(OUT_DIR, exist_ok=True)

old = os.path.join(PROJECT_DIR, PROJECT_NAME)
if os.path.exists(old):
    shutil.rmtree(old, ignore_errors=True)

os.environ["_JAVA_OPTIONS"] = "-Xmx12g -Xms4g -XX:+UseG1GC"

import pyghidra
pyghidra.start(install_dir=GHIDRA_INSTALL)

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.data import StringDataType, TerminatedStringDataType
from ghidra.program.model.address import AddressSet

print("=" * 70)
print("  define strings and decompile")
print("=" * 70)
sys.stdout.flush()

string_entries = []
with open(STRINGS_FILE, 'r', encoding='utf-8', errors='replace') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        m = re.match(r'0x([0-9A-Fa-f]+)\s+(.*)', line)
        if m:
            addr = int(m.group(1), 16)
            text = m.group(2)
            if len(text) >= 4 and addr < 0x01FC0000: 
                string_entries.append((addr, text))

print(f"[*] parsed {len(string_entries)} string entries from strings.txt")
sys.stdout.flush()

with pyghidra.open_program(
    PAYLOAD_PATH,
    project_location=PROJECT_DIR,
    project_name=PROJECT_NAME,
    language="x86:LE:64:default",
    compiler="windows"
) as flat_api:
    program = flat_api.getCurrentProgram()
    func_mgr = program.getFunctionManager()
    monitor = ConsoleTaskMonitor()
    listing = program.getListing()
    addr_factory = program.getAddressFactory()
    default_space = addr_factory.getDefaultAddressSpace()
    memory = program.getMemory()

    total_funcs = func_mgr.getFunctionCount()
    print(f"[*] image base: 0x{program.getImageBase().getOffset():x}")
    print(f"[*] total functions: {total_funcs}")
    sys.stdout.flush()

    print("[*] defining string data types...")
    defined = 0
    skipped = 0
    txn = program.startTransaction("define strings")
    try:
        for offset, text in string_entries:
            try:
                addr = default_space.getAddress(offset)
                if not memory.contains(addr):
                    skipped += 1
                    continue
                existing = listing.getDataAt(addr)
                if existing is not None:
                    listing.clearCodeUnits(addr, addr, False)
                try:
                    listing.createData(addr, TerminatedStringDataType.dataType)
                    defined += 1
                except Exception:
                    skipped += 1
            except Exception:
                skipped += 1

            if (defined + skipped) % 2000 == 0 and (defined + skipped) > 0:
                print(f"  [{defined + skipped}/{len(string_entries)}] {defined} defined, {skipped} skipped")
                sys.stdout.flush()
    finally:
        program.endTransaction(txn, True)

    print(f"[+] defined {defined} strings ({skipped} skipped)")
    sys.stdout.flush()

    print("[*] building function list...")
    func_list = []
    func_iter = func_mgr.getFunctions(True)
    while func_iter.hasNext():
        func = func_iter.next()
        if not func.isExternal():
            func_list.append(func)
    print(f"[*] {len(func_list)} functions to decompile")
    sys.stdout.flush()

    DECOMP_PATH = os.path.join(OUT_DIR, "dump_annotated.c")
    count = 0
    skip = 0
    errors = 0
    decomp = None
    CHUNK = 1000

    with open(DECOMP_PATH, "w", encoding="utf-8") as f:
        f.write("// ghidra decompilation of dump.bin\n")
        f.write(f"// image base 0x{program.getImageBase().getOffset():x}\n")
        f.write("// architecture x86_64 windows\n")
        f.write(f"// total functions {total_funcs}\n")
        f.write(f"// string definitions {defined}\n\n")

        for i, func in enumerate(func_list):
            if decomp is None or (i > 0 and i % CHUNK == 0):
                if decomp is not None:
                    decomp.dispose()
                    decomp = None
                    gc.collect()
                decomp = DecompInterface()
                decomp.openProgram(program)

            try:
                result = decomp.decompileFunction(func, 30, monitor)
                if result and not result.isCancelled():
                    d_func = result.getDecompiledFunction()
                    if d_func:
                        code = d_func.getC()
                        addr = str(func.getEntryPoint())
                        fname = func.getName()
                        size = func.getBody().getNumAddresses()
                        f.write(f"\n/* ============================================================\n")
                        f.write(f" * function: {fname}\n")
                        f.write(f" * address:  {addr}\n")
                        f.write(f" * size:     {size} bytes\n")
                        f.write(f" * ============================================================ */\n")
                        f.write(code)
                        f.write("\n")
                        count += 1
                        del code, d_func, result
                    else:
                        skip += 1
                        del result
                else:
                    skip += 1
                    if result:
                        del result
            except Exception as e:
                errors += 1
                if errors <= 10:
                    print(f"[!] Error: {func.getName()} @ {func.getEntryPoint()}: {e}")

            if (i + 1) % 500 == 0:
                f.flush()
                fsize = os.path.getsize(DECOMP_PATH)
                print(f"[*] {i+1}/{len(func_list)} | {count} ok, {skip} skip, {errors} err | {fsize/1024/1024:.1f}MB")
                sys.stdout.flush()

        f.flush()

    if decomp:
        decomp.dispose()

    fsize = os.path.getsize(DECOMP_PATH)
    print(f"\n[+] DONE: {count} decompiled, {skip} skipped, {errors} errors")
    print(f"[+] Output: {DECOMP_PATH} ({fsize/1024/1024:.1f} MB)")

    func_map_path = os.path.join(OUT_DIR, "dump_annotated_functions.txt")
    with open(func_map_path, "w", encoding="utf-8") as f:
        f.write("# function map for dump.bin with string annotations\n\n")
        for func in func_list:
            addr = func.getEntryPoint()
            size = func.getBody().getNumAddresses()
            f.write(f"0x{addr}  {size:6d}  {func.getName()}\n")
    print(f"[+] function map: {func_map_path}")
    sys.stdout.flush()

print("[*] all done")
