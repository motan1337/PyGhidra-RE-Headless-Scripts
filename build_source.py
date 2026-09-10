import re
import os
import sys
from collections import defaultdict

DECOMPILED = r"C:\Users\user\Documents\docs\docs\docs\ghidra_output\dump_annotated.c"
STRINGS_FILE = r"C:\Users\user\Documents\docs\docs\docs\memdump\strings.txt"
OUTPUT_DIR = r"C:\Users\user\Documents\docs\docs\reverse\source_organized"

os.makedirs(OUTPUT_DIR, exist_ok=True)

print("[Phase 1] Parsing strings and building category map...")

strings_by_addr = {}
with open(STRINGS_FILE, 'r', encoding='utf-8', errors='replace') as f:
    for line in f:
        m = re.match(r'0x([0-9A-Fa-f]+)\s+(.*)', line.strip())
        if m:
            addr = int(m.group(1), 16)
            text = m.group(2).strip()
            if len(text) >= 3:
                strings_by_addr[addr] = text

MODULES = {
    'ragebot': {
        'keywords': ['Ragebot', 'Hit Chance', 'Min Damage', 'Lowest Health',
                     'Closest To Crosshair', 'Closest Distance', 'silentactions',
                     'Silent Actions', 'doubletap', 'Double-Tap', 'antispread',
                     'Anti Spread', 'wallbanginfo', 'Wallbang Info', 'mindmg',
                     'hitchance', 'Visualize Aimbot', 'autowall', 'autoscope',
                     'autostop'],
        'desc': 'Aimbot / Ragebot module'
    },
    'antiaim': {
        'keywords': ['Yaw Offset', 'yawoffset', 'jitteraa', 'jitterrange',
                     'custompitch', 'Custom Pitch', 'desync', 'freestand',
                     'Freestand'],
        'desc': 'Anti-Aim module'
    },
    'visuals_esp': {
        'keywords': ['outofview', 'Out Of View', 'outofviewscale',
                     'dmgindicator', 'Damage Indicator', 'noscopeoverlay',
                     'noflash', 'No Flash', 'nadetracer', 'Grenade Tracer',
                     'recoilcrosshair', 'bullettracer',
                     'Bullet Tracers', 'spectators', 'Spectators', 'watermark',
                     'noscope', 'nolegs', 'killeffect', 'Kill Effect',
                     'Grenade Warning', 'nadewarning', 'Hit Effects', 'hiteffects'],
        'desc': 'Visuals / ESP module'
    },
    'world_effects': {
        'keywords': ['skybox', 'Skybox', 'skycolor', 'worldcolor',
                     'World Color', 'fogoverride', 'Override Fog', 'nosmoke',
                     'smokeoverride', 'suncolor', 'Sun Color',
                     'lightcolor', 'firecolor', 'Fire Color',
                     'explosioncolor', 'muzzleflashcolor', 'Muzzle Flash Color',
                     'cloudscolor', 'rainintensity', 'raincolor',
                     'rainglow', 'rainlightning', 'snowintensity', 'snowcolor',
                     'snowglow', 'ashintensity', 'ashcolor', 'ashglow',
                     'ashlightning', 'emberintensity', 'embercolor',
                     'antiobs', 'Anti-OBS', 'ambiencemenu', 'nightmode'],
        'desc': 'World effects / Weather module'
    },
    'console': {
        'keywords': ['unbindall', 'bindtoggle', 'bindhold',
                     'Unknown command', 'Command execution limit',
                     'AIMWARE Cheat Console', 'Clear console',
                     'Clear all binds'],
        'desc': 'Console / Command system'
    },
    'lua_engine': {
        'keywords': ['Lua Scripts', 'lua.load', 'lua.delete',
                     'lua.unloadall', 'lua_debug', 'luaperms',
                     'gamescript', 'luaopen_'],
        'desc': 'Lua 5.1 / LuaJIT scripting engine'
    },
    'lua_stdlib': {
        'keywords': ['table.new', 'table.clear', 'table.concat',
                     'table.insert', 'table.remove', 'table.sort',
                     'string.find', 'string.sub', 'string.format',
                     'string.match', 'string.gmatch', 'string.rep',
                     'math.sin', 'math.cos', 'math.floor',
                     'math.ceil', 'math.random', 'math.sqrt',
                     'io.open', 'io.read', 'io.write',
                     'os.clock', 'os.time', 'os.date'],
        'desc': 'Lua standard library functions'
    },
    'config': {
        'keywords': ['Load With Configurations', 'savecfg', 'cfg.load'],
        'desc': 'Config save/load system'
    },
    'render': {
        'keywords': ['Titillium Web', 'DrawRect', 'DrawLine',
                     'DrawFilledRect', 'BeginScene', 'EndScene'],
        'desc': 'Rendering / D3D overlay'
    },
    'weapon': {
        'keywords': ['Heavy Pistol', 'Auto Sniper', 'Submachine Gun',
                     'Light Machine Gun', 'Quick Stab', 'Only Backstab',
                     'Straight Throw', 'Quick Plant'],
        'desc': 'Weapon definitions and handling'
    },
    'misc_features': {
        'keywords': ['Viewmodel FOV', 'viewmodelfov', 'View FOV',
                     'Detonate Timer', 'Color Fade', 'bunnyhop',
                     'autostrafe', 'Fake Lag', 'fakelag',
                     'backtrack', 'Backtrack', 'clantag'],
        'desc': 'Misc features (FOV, movement, etc.)'
    },
    'crypto': {
        'keywords': ['SystemFunction036', 'advapi32.dll', 'wolfSSL',
                     'ssl_connect', 'ssl_read', 'ssl_write',
                     'certificate', 'RtlGenRandom'],
        'desc': 'Cryptographic functions'
    },
    'network': {
        'keywords': ['WinHTTP', 'winhttp', 'InternetOpen',
                     'HttpSendRequest', 'HttpOpenRequest',
                     'ActivationRequest', 'DeactivationRequest',
                     'BaseRequest'],
        'desc': 'Network / License authentication'
    },
    'anti_detect': {
        'keywords': ['NtQueryInformation', 'IsDebuggerPresent',
                     'CheckRemoteDebugger', 'ProcessDebugPort',
                     'ThreadHideFromDebugger'],
        'desc': 'Anti-detection / Anti-debug'
    },
    'memory': {
        'keywords': ['VirtualAlloc', 'VirtualProtect', 'VirtualFree',
                     'ReadProcessMemory', 'WriteProcessMemory',
                     'NtReadVirtualMemory', 'NtWriteVirtualMemory',
                     'MapViewOfFile'],
        'desc': 'Memory management / Process interaction'
    },
    'lua_runtime': {
        'keywords': ['isvararg', 'short_src', 'nparams', 'namewhat',
                     'currentline', 'linedefined', 'lastlinedefined',
                     '__tostring', '_LOADED',
                     'cannot switch from manual to aut',
                     'format specifier',
                     'precision is not integer', 'negative precision',
                     'negative width', 'number is too big',
                     'argument not found',
                     'unknown format specifier',
                     'string pointer is null',
                     'unmatched'],
        'desc': 'Lua runtime internals (debug, format, type system)'
    },
    'stl_containers': {
        'keywords': ['unordered_map', 'vector too long',
                     'basic_string', 'bad_alloc', 'length_error',
                     'invalid_argument', 'list iterator',
                     'string too long', 'invalid hash bucket'],
        'desc': 'C++ STL container implementations'
    },
    'ffi': {
        'keywords': ['kcdata', 'metatype', 'hardfp',
                     'ctype', 'cdata', 'C library'],
        'desc': 'LuaJIT FFI (Foreign Function Interface)'
    }
}

string_addr_to_module = {}
for addr, text in strings_by_addr.items():
    for mod_name, mod_info in MODULES.items():
        matched = False
        for kw in mod_info['keywords']:
            if kw.lower() in text.lower():
                key = f"{addr:08x}"
                string_addr_to_module[key] = mod_name
                matched = True
                break
        if matched:
            break

print(f"  {len(string_addr_to_module)} string addresses mapped to modules")

label_text_to_module = {}
for mod_name, mod_info in MODULES.items():
    for kw in mod_info['keywords']:
        normalized = kw.lower().replace(' ', '_')
        if len(normalized) >= 8:
            label_text_to_module[normalized] = mod_name

print("[Phase 2] First pass extracting function metadata from file...")
sys.stdout.flush()

func_order = []
func_calls = defaultdict(set)
func_strings = defaultdict(set)
func_addr = {}
func_module = {}
func_all_modules = defaultdict(lambda: defaultdict(int)) 

line_num = 0
current_func = None
func_count = 0

with open(DECOMPILED, 'r', encoding='utf-8') as f:
    for line in f:
        line_num += 1
        m = re.match(r' \* Function: (FUN_[0-9a-f]+)', line)
        if m:
            current_func = m.group(1)
            func_order.append(current_func)
            func_addr[current_func] = int(current_func[4:], 16)
            func_count += 1
            if func_count % 5000 == 0:
                print(f"  Scanned {func_count} functions...")
                sys.stdout.flush()
            continue
        if current_func:
            for cm in re.finditer(r'(FUN_[0-9a-f]+|thunk_FUN_[0-9a-f]+)\(', line):
                func_calls[current_func].add(cm.group(1))
            for sm in re.finditer(r's_(\w+)_([0-9a-f]{6,8})', line):
                label_text = sm.group(1).lower()
                addr_str = sm.group(2).lower()
                func_strings[current_func].add(sm.group(0))
                if addr_str in string_addr_to_module:
                    func_all_modules[current_func][string_addr_to_module[addr_str]] += 1
                for kw_lower, mod in label_text_to_module.items():
                    if kw_lower in label_text:
                        func_all_modules[current_func][mod] += 1
                        break

for fn, votes in func_all_modules.items():
    if votes:
        best_mod = max(votes, key=votes.get)
        func_module[fn] = best_mod

print(f"  Total: {func_count} functions scanned")
print(f"  {len(func_module)} functions classified by direct string references")

init_dist = defaultdict(int)
for mod in func_module.values():
    init_dist[mod] += 1
for mod, cnt in sorted(init_dist.items(), key=lambda x: -x[1]):
    print(f"    {mod}: {cnt}")
sys.stdout.flush()

print("[Phase 3] Conservative call graph propagation (max 3 rounds)...")

callers_of = defaultdict(set)
for fn, callees in func_calls.items():
    for callee in callees:
        callers_of[callee].add(fn)

UTILITY_THRESHOLD = 30
utility_funcs = set()
for fn, caller_set in callers_of.items():
    if len(caller_set) >= UTILITY_THRESHOLD:
        utility_funcs.add(fn)

print(f"  {len(utility_funcs)} utility functions (>={UTILITY_THRESHOLD} callers) excluded from propagation")

MAX_ROUNDS = 3
for rnd in range(1, MAX_ROUNDS + 1):
    new_assignments = 0
    for fn in func_order:
        if fn in func_module or fn in utility_funcs:
            continue
        my_callers = callers_of.get(fn, set())
        module_votes = defaultdict(int)
        for caller in my_callers:
            if caller in func_module:
                module_votes[func_module[caller]] += 1
        my_callees = func_calls.get(fn, set())
        for callee in my_callees:
            if callee in func_module and callee not in utility_funcs:
                module_votes[func_module[callee]] += 1

        if not module_votes:
            continue

        total_votes = sum(module_votes.values())
        best_mod = max(module_votes, key=module_votes.get)
        best_count = module_votes[best_mod]

        if best_count >= 2 and best_count / total_votes > 0.6:
            func_module[fn] = best_mod
            new_assignments += 1

    print(f"  Round {rnd}: {new_assignments} new (total: {len(func_module)})")
    if new_assignments == 0:
        break

prop_dist = defaultdict(int)
for mod in func_module.values():
    prop_dist[mod] += 1
print("  Post propagation distribution:")
for mod, cnt in sorted(prop_dist.items(), key=lambda x: -x[1]):
    print(f"    {mod}: {cnt}")

print(f"  After propagation: {len(func_module)} classified, {func_count - len(func_module)} remaining")
print("[Phase 4] Grouping remaining functions by address range...")

unclassified = [(func_addr[fn], fn) for fn in func_order if fn not in func_module]
unclassified.sort()

CHUNK_SIZE = 0x40000  # 256KB
addr_groups = defaultdict(list)
for addr, fn in unclassified:
    group_id = addr // CHUNK_SIZE
    addr_groups[group_id].append(fn)

chunk_names = {}
for group_id, funcs in sorted(addr_groups.items()):
    base = group_id * CHUNK_SIZE
    chunk_names[group_id] = f"code_{base:06x}_{base+CHUNK_SIZE:06x}"

print(f"  {len(addr_groups)} address range groups")

for fn in utility_funcs:
    if fn not in func_module:
        func_module[fn] = 'core_utility'

print("[Phase 5] Building final module map...")

module_funcs = defaultdict(list)
for fn in func_order:
    if fn in func_module:
        module_funcs[func_module[fn]].append(fn)
    else:
        addr = func_addr[fn]
        group_id = addr // CHUNK_SIZE
        name = chunk_names.get(group_id, f"code_{addr:06x}")
        module_funcs[name].append(fn)

print("\n  Module breakdown:")
for mod_name in sorted(module_funcs.keys()):
    funcs = module_funcs[mod_name]
    desc = MODULES.get(mod_name, {}).get('desc', '')
    print(f"    {mod_name}: {len(funcs)} functions" + (f" — {desc}" if desc else ""))

total_assigned = sum(len(v) for v in module_funcs.values())
print(f"\n  Total: {total_assigned} functions across {len(module_funcs)} files")
sys.stdout.flush()

print("\n[Phase 6] Second pass — extracting function bodies and writing files...")

func_to_file = {}
for mod_name, funcs in module_funcs.items():
    for fn in funcs:
        func_to_file[fn] = mod_name

file_handles = {}
file_func_counts = defaultdict(int)

def get_handle(mod_name):
    if mod_name not in file_handles:
        path = os.path.join(OUTPUT_DIR, f"{mod_name}.c")
        fh = open(path, 'w', encoding='utf-8')
        desc = MODULES.get(mod_name, {}).get('desc', mod_name)
        fh.write(f"// Module: {mod_name}\n")
        fh.write(f"// Description: {desc}\n")
        fh.write(f"// Source: Ghidra decompilation of dump.bin\n")
        fh.write(f"// Architecture: x86-64 (Windows)\n\n")
        file_handles[mod_name] = fh
    return file_handles[mod_name]

line_num = 0
current_func = None
current_mod = None
current_lines = []
func_written = 0

with open(DECOMPILED, 'r', encoding='utf-8') as f:
    for line in f:
        line_num += 1
        m = re.match(r' \* Function: (FUN_[0-9a-f]+)', line)
        if m:
            if current_func and current_lines:
                fh = get_handle(current_mod)
                for l in current_lines:
                    fh.write(l)
                fh.write("\n\n")
                file_func_counts[current_mod] += 1
                func_written += 1
                if func_written % 5000 == 0:
                    print(f"  Written {func_written} functions...")
                    sys.stdout.flush()

            current_func = m.group(1)
            current_mod = func_to_file.get(current_func, 'unknown')
            current_lines = []
            current_lines.append("/* ============================================================\n")
            current_lines.append(f" * Function: {current_func}\n")
            continue

        if line_num <= 7:
            continue

        if current_func:
            current_lines.append(line)

    if current_func and current_lines:
        fh = get_handle(current_mod)
        for l in current_lines:
            fh.write(l)
        file_func_counts[current_mod] += 1
        func_written += 1

for fh in file_handles.values():
    fh.close()

print(f"\n  Written {func_written} functions to {len(file_handles)} files")

print("[Phase 7] Writing module index...")

index_path = os.path.join(OUTPUT_DIR, "index.md")
with open(index_path, 'w', encoding='utf-8') as f:
    f.write("# dump.bin decompiled source code\n\n")
    f.write("organized decompilation of the dump payload.\n")
    f.write(f"total: {func_written} functions across {len(file_handles)} files.\n\n")
    f.write("## identified modules\n\n")
    f.write("| file | functions | description |\n")
    f.write("|------|-----------|-------------|\n")

    for mod_name in sorted(m for m in module_funcs if m in MODULES):
        count = file_func_counts.get(mod_name, 0)
        desc = MODULES[mod_name]['desc']
        f.write(f"| `{mod_name}.c` | {count} | {desc} |\n")

    if 'core_utility' in file_func_counts:
        f.write(f"| `core_utility.c` | {file_func_counts['core_utility']} | core utility functions (called 30+ times) |\n")

    f.write("\n## address range code chunks\n\n")
    f.write("functions not classified into a named module grouped by binary address\n\n")
    f.write("| file | functions | address range |\n")
    f.write("|------|-----------|---------------|\n")
    for mod_name in sorted(m for m in module_funcs if m.startswith('code_')):
        count = file_func_counts.get(mod_name, 0)
        parts = mod_name.split('_')
        f.write(f"| `{mod_name}.c` | {count} | `0x{parts[1]}` — `0x{parts[2]}` |\n")

    f.write("\n## key functions\n\n")
    f.write("| function | module | role |\n")
    f.write("|----------|--------|------|\n")
    f.write("| `FUN_00001fc5` | core fnv 1a hash lookup (variable name resolution)\n")
    f.write("| `FUN_0020c13c` | lua_runtime lua_getinfo implementation\n")
    f.write("| `FUN_0013ab18` | lua_runtime lua name resolution\n")
    f.write("| `FUN_00100764` | lua_engine lua.load / lua.unloadall\n")
    f.write("| `FUN_00243eb0` | lua_stdlib table.new / table.clear\n")
    f.write("| `FUN_00260612` | config savecfg / load with configurations\n")
    f.write("| `FUN_0020c852` | crypto rtlGenRandom (SystemFunction036)\n")
    f.write("| `FUN_00134313` | lua_runtime module loading\n")
    f.write(f"| `FUN_008e8f53` | core_utility most called function\n")
    f.write(f"| `thunk_FUN_00a11821` | core_utility\n")
    f.write(f"| `FUN_00cf681b` | core_utility\n")

print("\n" + "=" * 60)
print(f"OUTPUT DIRECTORY: {OUTPUT_DIR}")
print(f"TOTAL FILES:      {len(file_handles)}")
print(f"TOTAL FUNCTIONS:  {func_written}")
print("=" * 60)

total_size = 0
for fname in sorted(os.listdir(OUTPUT_DIR)):
    fpath = os.path.join(OUTPUT_DIR, fname)
    if os.path.isfile(fpath):
        size = os.path.getsize(fpath)
        total_size += size
        if size > 100000:
            print(f"  {fname}: {size/1024/1024:.1f} MB")
        elif size > 1000:
            print(f"  {fname}: {size/1024:.1f} KB")

print(f"\n  TOTAL SIZE: {total_size/1024/1024:.1f} MB")
print("\n[+] Done!")
