import re
import sys
from collections import defaultdict

DECOMPILED = r"C:\Users\motan\Documents\docs\docs\docs\ghidra_output\dump_annotated.c"

def fnv1a_64(s):
    h = 0xcbf29ce484222325
    for b in s.encode('utf-8'):
        h = ((h ^ b) * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h

# all known feature variable names from the strings dump
FEATURE_VARS = {
    'ragebot': [
        'silentactions', 'mindmg', 'hitchance', 'doubletap', 'antispread',
        'wallbanginfo', 'autoscope', 'autostop', 'autofire', 'resolver',
        'visualize', 'quickpeek', 'forcebaim', 'multipoint', 'hitscan',
        'headscale', 'bodyscale', 'safepoint', 'autorevolver',
    ],
    'antiaim': [
        'yawoffset', 'jitteraa', 'jitterrange', 'custompitch', 'freestand',
        'desync', 'fakelag', 'yawbase', 'pitchmode', 'spinspeed',
        'yawjitter', 'bodyyaw', 'edgeyaw',
    ],
    'visuals': [
        'outofview', 'outofviewscale', 'radar', 'dmgindicator',
        'noscopeoverlay', 'noflash', 'nadetracer', 'crosshair',
        'recoilcrosshair', 'bullettracer', 'spectators', 'watermark',
        'noscope', 'nolegs', 'killeffect', 'nadewarning', 'hiteffects',
        'hitmarker', 'chams', 'glow', 'skeleton', 'healthbar', 'ammobar',
        'dormant', 'snaplines', 'outofviewarrows', 'drawweapon',
        'drawammo', 'drawmoney', 'drawname', 'drawhealth', 'drawarmor',
        'drawflags', 'boxesp', 'filledesp',
    ],
    'world': [
        'skybox', 'skycolor', 'worldcolor', 'fogoverride', 'nosmoke',
        'smokeoverride', 'suncolor', 'lightcolor', 'firecolor',
        'explosioncolor', 'muzzleflashcolor', 'cloudscolor',
        'rainintensity', 'raincolor', 'rainglow', 'rainlightning',
        'snowintensity', 'snowcolor', 'snowglow',
        'ashintensity', 'ashcolor', 'ashglow', 'ashlightning',
        'emberintensity', 'embercolor', 'antiobs', 'nightmode',
        'ambiencemenu', 'nosky', 'nofog',
    ],
    'misc': [
        'viewmodelfov', 'viewfov', 'bunnyhop', 'autostrafe',
        'backtrack', 'clantag', 'namestealer', 'hitsound',
        'killsound', 'thirdperson', 'thirdpersondist',
        'revealranks', 'autoacceptmatch', 'chatspam',
        'autodefuse', 'autoplant', 'zeusbot',
    ],
    'weapon': [
        'autopistol', 'norecoil', 'nospread',
    ],
}

print("[*] computing  fnv 1a hashes of feature variable names...\n")
hash_to_feature = {}
for module, names in FEATURE_VARS.items():
    for name in names:
        h = fnv1a_64(name)
        hex_h = f"0x{h:x}"
        hash_to_feature[hex_h] = (module, name)
        h32 = h & 0xFFFFFFFF
        hash_to_feature[f"0x{h32:x}"] = (module, name)

print(f"[*] {len(hash_to_feature)} hash values to search for\n")

print("sample hashes:")
for module, names in list(FEATURE_VARS.items())[:3]:
    for name in names[:3]:
        h = fnv1a_64(name)
        print(f"  {name:25s} -> 0x{h:016x}  (low32: 0x{h & 0xFFFFFFFF:08x})")
    print()

print(f"[*] scanning decompiled output for hash constants...")
sys.stdout.flush()

func_features = defaultdict(set)
current_func = None
line_num = 0
matches = 0

with open(DECOMPILED, 'r', encoding='utf-8') as f:
    for line in f:
        line_num += 1
        m = re.match(r' \* Function: (FUN_[0-9a-f]+)', line)
        if m:
            current_func = m.group(1)
            continue

        if current_func:
            for hm in re.finditer(r'0x([0-9a-f]+)', line):
                hex_val = f"0x{hm.group(1)}"
                if hex_val in hash_to_feature:
                    module, name = hash_to_feature[hex_val]
                    func_features[current_func].add((module, name))
                    matches += 1

        if line_num % 500000 == 0:
            print(f"  scanned {line_num} lines, {matches} hash matches so far...")
            sys.stdout.flush()

print(f"\n[*] total: {matches} hash matches in {len(func_features)} functions\n")

module_funcs = defaultdict(list)
for fn, features in func_features.items():
    modules = set(m for m, n in features)
    vars_found = [(m, n) for m, n in features]
    for m in modules:
        module_funcs[m].append((fn, [n for mm, n in vars_found if mm == m]))

print("=" * 60)
print("feature functuons found by fnv 1a hash matching")
print("=" * 60)
for module in sorted(module_funcs.keys()):
    funcs = module_funcs[module]
    print(f"\n{module.upper()} ({len(funcs)} functions):")
    for fn, vars_found in sorted(funcs, key=lambda x: x[0]):
        print(f"  {fn}: {', '.join(sorted(vars_found))}")

out_path = r"C:\Users\user\Documents\docs\docs\docs\source\hash_matches.txt"
with open(out_path, 'w', encoding='utf-8') as f:
    f.write("fnv 1a hash match results\n")
    f.write("=" * 60 + "\n\n")
    for module in sorted(module_funcs.keys()):
        funcs = module_funcs[module]
        f.write(f"\n{module.upper()} ({len(funcs)} functions):\n")
        for fn, vars_found in sorted(funcs, key=lambda x: x[0]):
            f.write(f"  {fn}: {', '.join(sorted(vars_found))}\n")

print(f"\n[+] results saved to {out_path}")
