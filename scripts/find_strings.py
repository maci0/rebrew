import re
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

from rebrew.annotation import parse_c_file
from rebrew.cli import get_config


def extract_string(data: bytes) -> str:
    res = bytearray()
    for b in data:
        if b == 0:
            break
        if 32 <= b <= 126 or b in (9, 10, 13):
            res.append(b)
        else:
            return ""
    if len(res) >= 3:
        return res.decode("utf-8")
    return ""


def main():
    cfg = get_config(target="server.dll")
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False

    src_dir = Path(cfg.reversed_dir)
    unknowns = []
    for cfile in src_dir.glob("func_*.c"):
        try:
            entry = parse_c_file(cfile)
            if entry and entry.status not in ("EXACT", "RELOC"):
                unknowns.append((cfile, entry))
        except Exception:
            pass

    print(f"Analyzing {len(unknowns)} unknown functions for string references...")

    for cfile, entry in sorted(unknowns, key=lambda x: x[1].va):
        try:
            data = cfg.extract_dll_bytes(entry.va, entry.size)
        except Exception:
            continue

        found_strings = set()
        for insn in md.disasm(data, entry.va):
            match = re.search(r"0x(1[01][0-9a-f]{5})", insn.op_str)
            if match:
                ptr = int(match.group(1), 16)
                if ptr > entry.va + entry.size or ptr < entry.va:
                    try:
                        sz_data = cfg.extract_dll_bytes(ptr, 64)
                        s = extract_string(sz_data)
                        if s:
                            found_strings.add(s)
                    except Exception:
                        pass

        if found_strings:
            print(f"VA: 0x{entry.va:08x} (Size: {entry.size}) File: {cfile.name}")
            for s in found_strings:
                print(f"  -> '{s}'")


if __name__ == "__main__":
    main()
