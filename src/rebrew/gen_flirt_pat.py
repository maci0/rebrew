#!/usr/bin/env python3
"""Generate FLIRT .pat files from MSVC6 COFF .lib archives.

This reads the object files inside a .lib archive, extracts every
public function symbol with its COFF relocations, and emits a
.pat-format line for each one with relocation bytes masked as '..'.

Usage: uv run python tools/gen_flirt_pat.py tools/MSVC600/VC98/Lib/LIBCMT.LIB -o flirt_sigs/libcmt_vc6.pat
"""

import struct
import sys
import os
import argparse


def parse_archive(lib_path):
    """Parse a COFF archive (.lib) and yield (member_name, obj_data) tuples."""
    with open(lib_path, 'rb') as f:
        data = f.read()

    if not data.startswith(b'!<arch>\n'):
        raise ValueError(f"{lib_path} is not a valid archive")

    pos = 8
    while pos < len(data):
        if pos % 2 == 1:
            pos += 1
        if pos + 60 > len(data):
            break

        header = data[pos:pos + 60]
        name_field = header[0:16].rstrip(b' ')
        size = int(header[48:58].strip())

        pos += 60
        member_data = data[pos:pos + size]
        pos += size

        name = name_field.decode('ascii', errors='replace').rstrip('/')

        if name in ('', '/', '//'):
            continue

        yield name, member_data


def parse_coff_obj(obj_data):
    """Parse a COFF .obj and yield (symbol_name, code_bytes, reloc_offsets)."""
    if len(obj_data) < 20:
        return

    machine = struct.unpack_from('<H', obj_data, 0)[0]
    if machine not in (0x14c, 0):
        return

    num_sections = struct.unpack_from('<H', obj_data, 2)[0]
    sym_offset = struct.unpack_from('<I', obj_data, 8)[0]
    num_symbols = struct.unpack_from('<I', obj_data, 12)[0]

    if sym_offset == 0 or num_symbols == 0:
        return

    str_tab_off = sym_offset + num_symbols * 18
    if str_tab_off + 4 > len(obj_data):
        return

    def get_sym_name(entry):
        if entry[:4] == b'\x00\x00\x00\x00':
            offset = struct.unpack_from('<I', entry, 4)[0]
            try:
                end = obj_data.index(b'\x00', str_tab_off + offset)
                return obj_data[str_tab_off + offset:end].decode('ascii', errors='replace')
            except (ValueError, IndexError):
                return None
        return entry[:8].rstrip(b'\x00').decode('ascii', errors='replace')

    # Parse sections: (name, raw_ptr, raw_size, characteristics, reloc_ptr, num_relocs)
    sections = []
    off = 20
    for _ in range(num_sections):
        if off + 40 > len(obj_data):
            break
        sec = obj_data[off:off + 40]
        sec_name = sec[0:8].rstrip(b'\x00').decode('ascii', errors='replace')
        raw_size = struct.unpack_from('<I', sec, 16)[0]
        raw_ptr = struct.unpack_from('<I', sec, 20)[0]
        reloc_ptr = struct.unpack_from('<I', sec, 24)[0]
        num_relocs = struct.unpack_from('<H', sec, 32)[0]
        characteristics = struct.unpack_from('<I', sec, 36)[0]
        sections.append((sec_name, raw_ptr, raw_size, characteristics, reloc_ptr, num_relocs))
        off += 40

    # Find function symbols
    i = 0
    while i < num_symbols:
        entry = obj_data[sym_offset + i * 18:sym_offset + i * 18 + 18]
        if len(entry) < 18:
            break
        name = get_sym_name(entry)
        value = struct.unpack_from('<I', entry, 8)[0]
        sec_num = struct.unpack_from('<h', entry, 12)[0]
        storage_class = entry[16]
        num_aux = entry[17]

        if name and sec_num > 0 and storage_class == 2:
            sec_idx = sec_num - 1
            if sec_idx < len(sections):
                sec_name, raw_ptr, raw_size, chars, reloc_ptr, num_relocs = sections[sec_idx]
                if chars & 0x20:  # IMAGE_SCN_CNT_CODE
                    func_start = value
                    func_end = raw_size
                    j = 0
                    while j < num_symbols:
                        e2 = obj_data[sym_offset + j * 18:sym_offset + j * 18 + 18]
                        if len(e2) < 18:
                            break
                        v2 = struct.unpack_from('<I', e2, 8)[0]
                        s2 = struct.unpack_from('<h', e2, 12)[0]
                        if s2 == sec_num and v2 > func_start and v2 < func_end:
                            n2 = get_sym_name(e2)
                            if n2 and not n2.startswith('$'):
                                func_end = v2
                        j += 1 + e2[17]

                    if raw_ptr + func_end <= len(obj_data):
                        code = obj_data[raw_ptr + func_start:raw_ptr + func_end]

                        # Parse COFF relocations for this function
                        reloc_offsets = set()
                        for ri in range(num_relocs):
                            roff = reloc_ptr + ri * 10
                            if roff + 10 > len(obj_data):
                                break
                            rva = struct.unpack_from('<I', obj_data, roff)[0]
                            rtype = struct.unpack_from('<H', obj_data, roff + 8)[0]
                            # rva is offset within section
                            if func_start <= rva < func_end:
                                func_rel = rva - func_start
                                # IMAGE_REL_I386_DIR32 (0x06) and
                                # IMAGE_REL_I386_REL32 (0x14) are 4-byte fixups
                                if rtype in (0x06, 0x14):
                                    for k in range(4):
                                        reloc_offsets.add(func_rel + k)
                                # IMAGE_REL_I386_DIR16 (0x01) is 2-byte
                                elif rtype == 0x01:
                                    for k in range(2):
                                        reloc_offsets.add(func_rel + k)

                        if len(code) >= 4:
                            yield name, code, reloc_offsets

        i += 1 + num_aux


def bytes_to_pat_line(name, code_bytes, reloc_offsets, max_lead=32):
    """Convert function name + bytes into a FLIRT .pat format line.

    Relocation bytes are masked with '..' in the leading portion.
    """
    lead_len = min(len(code_bytes), max_lead)
    lead = ''
    for i in range(lead_len):
        if i in reloc_offsets:
            lead += '..'
        else:
            lead += f'{code_bytes[i]:02X}'

    # CRC16 of non-reloc bytes after the leading portion
    crc_start = lead_len
    crc_len = min(len(code_bytes) - crc_start, 255)

    crc = 0
    for i in range(crc_start, crc_start + crc_len):
        b = 0 if i in reloc_offsets else code_bytes[i]
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x8005
            else:
                crc = crc << 1
            crc &= 0xFFFF

    total_size = len(code_bytes)

    return f'{lead} {crc_len:02X} {crc:04X} {total_size:04X} :0000 {name}'


def main():
    parser = argparse.ArgumentParser(description='Generate FLIRT .pat from COFF .lib')
    parser.add_argument('lib_path', help='Path to .lib file')
    parser.add_argument('-o', '--output', help='Output .pat file path')
    args = parser.parse_args()

    lib_path = args.lib_path
    if not os.path.exists(lib_path):
        print(f"ERROR: {lib_path} not found")
        sys.exit(1)

    lib_name = os.path.splitext(os.path.basename(lib_path))[0].lower()
    out_path = args.output or f'flirt_sigs/{lib_name}_vc6.pat'

    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    pat_lines = []
    seen = set()

    for member_name, obj_data in parse_archive(lib_path):
        try:
            for sym_name, code, relocs in parse_coff_obj(obj_data):
                if sym_name not in seen and len(code) >= 4:
                    seen.add(sym_name)
                    line = bytes_to_pat_line(sym_name, code, relocs)
                    pat_lines.append(line)
        except Exception:
            pass

    with open(out_path, 'w') as f:
        for line in pat_lines:
            f.write(line + '\n')
        f.write('---\n')

    print(f"Generated {out_path}: {len(pat_lines)} signatures from {lib_path}")


if __name__ == '__main__':
    main()
