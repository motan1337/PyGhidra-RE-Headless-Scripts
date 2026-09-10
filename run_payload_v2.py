import os
import sys
import gc
import shutil

GHIDRA_INSTALL = r"C:\Users\user\Documents\docs\docs\docs\ghidra_12.1.2_PUBLIC"
OUT_DIR = r"C:\Users\user\Documents\docs\docs\docs\ghidra_output"
PROJECT_DIR = r"C:\Users\user\Documents\docs\docs\docs\ghidra_projects"
PAYLOAD_PATH = r"C:\Users\user\Documents\docs\docs\docs\memdump\dump.bin"
PROJECT_NAME = "Payload_v2"

DECOMP_PATH = os.path.join(OUT_DIR, "dump.bin_decompiled.c")

os.makedirs(OUT_DIR, exist_ok=True)

for d in os.listdir(PROJECT_DIR):
    full = os.path.join(PROJECT_DIR, d)
    if os.path.isdir(full) and d.startswith("Payload"):
        shutil.rmtree(full, ignore_errors=True)
        print(f"[*] cleaned {d}")

os.environ["_JAVA_OPTIONS"] = "-Xmx12g -Xms4g -XX:+UseG1GC"

import pyghidra
pyghidra.start(install_dir=GHIDRA_INSTALL)

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

print("=" * 70)
print("  payload decompilation v2")
print("  12GB heap, G1GC, decompiler reset every 1000 functions")
print("=" * 70)
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

    total_funcs = func_mgr.getFunctionCount()
    print(f"[*] image base 0x{program.getImageBase().getOffset():x}")
    print(f"[*] total functions {total_funcs}")
    sys.stdout.flush()

    print("[*] building function list...")
    func_list = []
    func_iter = func_mgr.getFunctions(True)
    while func_iter.hasNext():
        func = func_iter.next()
        if not func.isExternal():
            func_list.append(func)
    print(f"[*] {len(func_list)} non external functions to decompile")
    sys.stdout.flush()

    count = 0
    skipped = 0
    errors = 0
    decomp = None
    CHUNK = 1000

    with open(DECOMP_PATH, "w", encoding="utf-8") as f:
        f.write("// ghidra decompilation of dump.bin\n")
        f.write(f"// image base 0x{program.getImageBase().getOffset():x}\n")
        f.write("// architecture x86_64 windows\n")
        f.write(f"// total functions {total_funcs}\n\n")

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
                        skipped += 1
                        del result
                else:
                    skipped += 1
                    if result:
                        del result
            except Exception as e:
                errors += 1
                if errors <= 20:
                    print(f"[!] Error: {func.getName()} @ {func.getEntryPoint()}: {e}")

            if (i + 1) % 500 == 0:
                f.flush()
                fsize = os.path.getsize(DECOMP_PATH)
                print(f"[*] {i+1}/{len(func_list)} processed | {count} ok, {skipped} skip, {errors} err | {fsize/1024/1024:.1f}MB")
                sys.stdout.flush()

        f.flush()

    if decomp:
        decomp.dispose()

    fsize = os.path.getsize(DECOMP_PATH)
    print(f"\n[+] done: {count} decompiled, {skipped} skipped, {errors} errors")
    print(f"[+] output: {DECOMP_PATH} ({fsize/1024/1024:.1f} MB)")
    print(f"[+] lines: ", end="")
    sys.stdout.flush()

    func_map_path = os.path.join(OUT_DIR, "dump.bin_functions.txt")
    with open(func_map_path, "w", encoding="utf-8") as f:
        f.write("# function map for dump.bin\n\n")
        for func in func_list:
            addr = func.getEntryPoint()
            size = func.getBody().getNumAddresses()
            f.write(f"0x{addr}  {size:6d}  {func.getName()}\n")
    print(f"\n[+] function map: {func_map_path}")
    sys.stdout.flush()

print("[*] All done!!!")
