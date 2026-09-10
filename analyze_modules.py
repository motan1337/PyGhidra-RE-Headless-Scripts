import re
import os
from collections import defaultdict

DECOMPILED = r"C:\Users\user\Documents\docs\docs\docs\ghidra_output\file.c"
STRINGS_FILE = r"C:\Users\user\Documents\docs\docs\docs\memdump\file.txt"
FUNC_MAP = r"C:\Users\user\Documents\docs\docs\docs\ghidra_output\file.txt"
OUTPUT_DIR = r"C:\Users\user\Documents\docs\docs\reverse\source"

os.makedirs(OUTPUT_DIR, exist_ok=True)

print("[*] Parsing strings...")
strings = []
with open(STRINGS_FILE, 'r', encoding='utf-8', errors='replace') as f:
    for line in f:
        m = re.match(r'0x([0-9A-Fa-f]+)\s+(.*)', line.strip())
        if m:
            addr = int(m.group(1), 16)
            text = m.group(2).strip()
            if len(text) >= 4:
                strings.append((addr, text))

string_categories = {}
CATEGORIES = {
    'ragebot': ['Ragebot', 'Hit Chance', 'Min Damage', 'Lowest Health',
                'Closest To Crosshair', 'Closest Distance', 'silentactions',
                'Silent Actions', 'doubletap', 'Double-Tap', 'antispread',
                'Anti Spread', 'wallbanginfo', 'Wallbang Info', 'mindmg',
                'hitchance', 'Visualize Aimbot', 'visualize'],
    'antiaim': ['Yaw Offset', 'yawoffset', 'Jitter', 'jitteraa', 'jitterrange',
                'Jitter Range', 'Spin', 'custompitch', 'Custom Pitch'],
    'visuals': ['Radar', 'radar', 'outofview', 'Out Of View', 'outofviewscale',
                'dmgindicator', 'Damage Indicator', 'noscopeoverlay', 'No Scope',
                'noflash', 'No Flash', 'nadetracer', 'Grenade Tracer',
                'crosshair', 'Crosshair', 'recoilcrosshair', 'bullettracer',
                'Bullet Tracers', 'spectators', 'Spectators', 'watermark',
                'noscope', 'nolegs', 'killeffect', 'Kill Effect',
                'Grenade Warning', 'nadewarning', 'Hit Effects', 'hiteffects'],
    'world': ['skybox', 'Skybox', 'skycolor', 'Sky Color', 'worldcolor',
              'World Color', 'fogoverride', 'Override Fog', 'nosmoke', 'No Smoke',
              'smokeoverride', 'Smoke Color', 'suncolor', 'Sun Color',
              'lightcolor', 'Light Color', 'firecolor', 'Fire Color',
              'explosioncolor', 'muzzleflashcolor', 'Muzzle Flash Color',
              'cloudscolor', 'Clouds Color', 'rainintensity', 'raincolor',
              'rainglow', 'rainlightning', 'snowintensity', 'snowcolor',
              'snowglow', 'ashintensity', 'ashcolor', 'ashglow', 'ashlightning',
              'emberintensity', 'embercolor', 'antiobs', 'Anti-OBS',
              'Effects Removal', 'No Sky', 'Ambience', 'ambiencemenu', 'inferno'],
    'console': ['bind ', 'unbind', 'unbindall', 'bindtoggle', 'bindhold',
                'Unknown command', 'Command execution limit', 'alias',
                'AIMWARE Cheat Console', 'savecfg', 'cfg.load',
                'Clear console', 'commands', 'cmds', 'Clear all binds'],
    'lua': ['Lua 5.1', 'Lua Scripts', 'luaperms', 'lua.load', 'lua.delete',
            'lua.unloadall', 'lua_debug', 'Unload lua', 'Load lua',
            'Run lua', 'Reset lua', 'gamescript', 'PANIC'],
    'weapon': ['pistol', 'Heavy Pistol', 'shotgun', 'Shotgun', 'sniper',
               'Auto Sniper', 'Submachine Gun', 'Light Machine Gun', 'Rifle',
               'Knife', 'Quick Stab', 'Only Backstab', 'Straight Throw',
               'Quick Plant'],
    'config': ['Load With Configurations', 'savecfg'],
    'render': ['Consolas', 'Titillium Web', 'font-size', 'Circle'],
    'misc': ['Viewmodel FOV', 'viewmodelfov', 'View FOV', 'View Direction',
             'Detonate Timer', 'Color Fade']
}

for addr, text in strings:
    for cat, keywords in CATEGORIES.items():
        for kw in keywords:
            if kw.lower() in text.lower():
                string_categories[addr] = (cat, text)
                break

print(f"[*] {len(string_categories)} strings categorized")
for cat in CATEGORIES:
    count = sum(1 for v in string_categories.values() if v[0] == cat)
    if count:
        print(f"    {cat}: {count}")

cat_ranges = defaultdict(list)
for addr, (cat, text) in sorted(string_categories.items()):
    cat_ranges[cat].append(addr)

print("\n[*] String address ranges by module:")
for cat, addrs in sorted(cat_ranges.items()):
    if addrs:
        print(f"    {cat}: 0x{min(addrs):06x} - 0x{max(addrs):06x} ({len(addrs)} strings)")

print("\n[*] Parsing function map...")
functions = []
with open(FUNC_MAP, 'r', encoding='utf-8') as f:
    for line in f:
        m = re.match(r'0x([0-9a-f]+)\s+(\d+)\s+(\S+)', line)
        if m:
            addr = int(m.group(1), 16)
            size = int(m.group(2))
            name = m.group(3)
            functions.append((addr, size, name))

print(f"[*] {len(functions)} functions in map")

print("\n[*] Parsing decompiled code for cross references...")
func_calls = defaultdict(set)  # func set of called functions
func_strings_found = defaultdict(set)  # func set of s_ labels

with open(DECOMPILED, 'r', encoding='utf-8') as f:
    current_func = None
    for line in f:
        m = re.match(r' \* Function: (FUN_[0-9a-f]+)', line)
        if m:
            current_func = m.group(1)
            continue
        if current_func:
            # find function calls
            for cm in re.finditer(r'(FUN_[0-9a-f]+|thunk_FUN_[0-9a-f]+|func_0x[0-9a-f]+)\(', line):
                func_calls[current_func].add(cm.group(1))
            # find string labels
            for sm in re.finditer(r'(s_\w+_[0-9a-f]{6,8})', line):
                func_strings_found[current_func].add(sm.group(1))

print(f"[*] {len(func_calls)} functions make calls")
print(f"[*] {len(func_strings_found)} functions reference labeled strings")

# find functions that call many other functions (likely init/main functions)
top_callers = sorted(func_calls.items(), key=lambda x: len(x[1]), reverse=True)[:20]
print("\n[*] Top function callers (likely init/dispatcher functions):")
for fn, calls in top_callers:
    strs = list(func_strings_found.get(fn, set()))[:3]
    print(f"    {fn}: calls {len(calls)} functions" + (f" strings: {strs}" if strs else ""))

# find functions called by many others (likely utility/core functions)
call_count = defaultdict(int)
for fn, calls in func_calls.items():
    for c in calls:
        call_count[c] += 1
top_called = sorted(call_count.items(), key=lambda x: x[1], reverse=True)[:20]
print("\n[*] Most called functions (likely utility/core):")
for fn, cnt in top_called:
    strs = list(func_strings_found.get(fn, set()))[:3]
    print(f"    {fn}: called {cnt} times" + (f" strings: {strs}" if strs else ""))

# find functions with the most string references (feature implementation)
top_stringy = sorted(func_strings_found.items(), key=lambda x: len(x[1]), reverse=True)[:30]
print("\n[*] Functions with most string references (feature implementations):")
for fn, strs in top_stringy:
    print(f"    {fn}: {len(strs)} strings — {list(strs)[:5]}")

report_path = os.path.join(OUTPUT_DIR, "ANALYSIS.txt")
with open(report_path, 'w', encoding='utf-8') as f:
    f.write("dump.bin Module Analysis\n")
    f.write("=" * 60 + "\n\n")

    f.write("STRING CATEGORIES:\n")
    for cat in CATEGORIES:
        count = sum(1 for v in string_categories.values() if v[0] == cat)
        if count:
            f.write(f"  {cat}: {count} strings\n")
            for addr, (c, text) in sorted(string_categories.items()):
                if c == cat:
                    f.write(f"    0x{addr:06x}  {text}\n")
            f.write("\n")

    f.write("\nTOP CALLERS (init/dispatcher functions):\n")
    for fn, calls in top_callers:
        strs = list(func_strings_found.get(fn, set()))
        f.write(f"  {fn}: calls {len(calls)} functions\n")
        if strs:
            for s in strs:
                f.write(f"    string: {s}\n")

    f.write("\nMOST CALLED (utility/core functions):\n")
    for fn, cnt in top_called:
        f.write(f"  {fn}: called {cnt} times\n")

    f.write("\nFUNCTIONS WITH MOST STRING REFS:\n")
    for fn, strs in top_stringy:
        f.write(f"  {fn}: {len(strs)} strings\n")
        for s in sorted(strs):
            f.write(f"    {s}\n")

print(f"\n[+] Analysis report: {report_path}")
print("[*] Done")