import re
import os

STRINGS_FILE = r"C:\Users\user\Documents\docs\docs\docs\memdump\strings.txt"
OUTPUT_DIR = r"C:\Users\user\docs\docs\docs\reverse\source_organized"

strings = []
with open(STRINGS_FILE, 'r', encoding='utf-8', errors='replace') as f:
    for line in f:
        m = re.match(r'0x([0-9A-Fa-f]+)\s+(.*)', line.strip())
        if m:
            addr = int(m.group(1), 16)
            text = m.group(2).strip()
            if len(text) >= 6 and not text.startswith('\\x'):
                printable = sum(1 for c in text if c.isprintable())
                if printable / max(len(text), 1) > 0.8:
                    strings.append((addr, text))

CHUNK_SIZE = 0x40000

chunk_strings = {}
for addr, text in strings:
    chunk_id = addr // CHUNK_SIZE
    base = chunk_id * CHUNK_SIZE
    name = f"code_{base:06x}_{base+CHUNK_SIZE:06x}"
    if name not in chunk_strings:
        chunk_strings[name] = []
    chunk_strings[name].append((addr, text))

for name, strs in chunk_strings.items():
    fpath = os.path.join(OUTPUT_DIR, f"{name}.c")
    if not os.path.exists(fpath):
        continue

    with open(fpath, 'r', encoding='utf-8') as f:
        content = f.read()

    header_end = content.find('\n\n')
    if header_end == -1:
        header_end = 0

    interesting = [s for s in strs if len(s[1]) >= 4]
    interesting.sort(key=lambda x: x[0])

    annotation = "\n// Strings in this address range\n"
    shown = 0
    for addr, text in interesting:
        if shown >= 80:
            annotation += f"// ... and {len(interesting) - shown} more strings\n"
            break
        safe = text[:100].replace('*/', '*//*')
        annotation += f"// 0x{addr:06x}: {safe}\n"
        shown += 1
    annotation += "// End of strings\n"

    new_content = content[:header_end] + annotation + content[header_end:]
    with open(fpath, 'w', encoding='utf-8') as f:
        f.write(new_content)

    print(f"  {name}: {shown} strings annotated")

print("\n[+] Done annotating chunks")
