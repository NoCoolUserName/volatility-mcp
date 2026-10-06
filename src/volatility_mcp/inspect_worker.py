"""Bounded static inspection worker. Never loads or executes recovered PE code."""
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys

MAX_FILE = 64 * 1024 * 1024


def pe_headers(data):
    import pefile
    result = {'mz_signature': data[:2] == b'MZ', 'pe_signature': False,
              'structural_status': 'not_pe', 'warnings': [], 'sections': [],
              'limitations': ['Header declarations are not proof of execution, maliciousness, or original-file identity.',
                              'Present raw ranges cannot establish recovery of missing or zero-filled memory pages.',
                              'Imports, signatures, resources and code are not executed or exhaustively validated.']}
    if not result['mz_signature']:
        return result
    result['structural_status'] = 'malformed_or_truncated'
    if len(data) < 64:
        result['warnings'].append('Truncated DOS header')
        return result
    start = struct.unpack_from('<I', data, 60)[0]
    result['pe_header_offset'] = start
    if start < 64 or start + 24 > len(data) or data[start:start+4] != b'PE\0\0':
        result['warnings'].append('PE signature/COFF header absent, out of bounds, or overlapping DOS header')
        return result
    result['pe_signature'] = True
    machine, count, timestamp, _, _, optsize, flags = struct.unpack_from('<HHIIIHH', data, start+4)
    result.update(machine={'value': machine, 'name': pefile.MACHINE_TYPE.get(machine, 'unknown')},
                  characteristics=flags, dll_flag=bool(flags & 0x2000), executable_image_flag=bool(flags & 2),
                  declared_section_count=count, coff_timestamp=timestamp,
                  classification='DLL flag set' if flags & 0x2000 else
                  'executable-image flag set; DLL flag not set' if flags & 2 else 'neither DLL nor executable-image flag set')
    opt = start + 24
    if opt + 2 > len(data):
        result['warnings'].append('Missing optional-header magic')
        return result
    magic = struct.unpack_from('<H', data, opt)[0]
    result['format'] = {0x10b: 'PE32', 0x20b: 'PE32+'}.get(magic, 'unknown')
    minimum = {0x10b: 96, 0x20b: 112}.get(magic)
    if minimum is None or optsize < minimum or opt + optsize > len(data):
        result['warnings'].append('Unsupported or truncated optional header')
        return result
    if not 1 <= count <= 96:
        result['warnings'].append('Section count outside bounded inspection limit 1..96')
        return result
    section_start = opt + optsize
    if section_start + count * 40 > len(data):
        result['warnings'].append('Truncated declared section table')
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        result['warnings'].append('pefile: ' + str(exc))
        return result
    try:
        optional = pe.OPTIONAL_HEADER
        result.update(image_base=optional.ImageBase, size_of_image=optional.SizeOfImage,
                      size_of_headers=optional.SizeOfHeaders,
                      subsystem={'value': optional.Subsystem, 'name': pefile.SUBSYSTEM_TYPE.get(optional.Subsystem, 'unknown')},
                      entry_point={'rva': optional.AddressOfEntryPoint,
                                   'preferred_va': optional.ImageBase + optional.AddressOfEntryPoint,
                                   'file_offset': None})
        if optional.SizeOfHeaders > len(data) or optional.SizeOfHeaders < section_start + count * 40:
            result['warnings'].append('SizeOfHeaders inconsistent with file/section table')
        for i, section in enumerate(pe.sections):
            begin, size = section.PointerToRawData, section.SizeOfRawData
            available = min(size, max(0, len(data) - begin))
            result['sections'].append({'index': i, 'name': section.Name.rstrip(b'\0').decode('ascii', errors='replace'),
                'rva': section.VirtualAddress, 'virtual_size': section.Misc_VirtualSize,
                'raw_offset': begin, 'raw_size': size, 'available_raw_bytes': available,
                'raw_range_present': available == size, 'characteristics': section.Characteristics})
            if available != size or (size and begin < optional.SizeOfHeaders):
                result['warnings'].append(f'Section {i} raw range truncated or overlaps headers')
            ep = optional.AddressOfEntryPoint - section.VirtualAddress
            if 0 <= ep < available:
                result['entry_point']['file_offset'] = begin + ep
        if len(pe.sections) != count:
            result['warnings'].append('Not all declared section headers were readable')
        if optional.AddressOfEntryPoint and result['entry_point']['file_offset'] is None:
            result['warnings'].append('Entry point does not map to an available section raw range')
        result['structural_status'] = 'truncated_or_inconsistent' if result['warnings'] else 'declared_ranges_present'
        result['parser_warnings'] = pe.get_warnings()[:32]
        return result
    finally:
        pe.close()


def strings_page(stream, size, settings):
    offset, budget, minimum = settings['offset'], settings['scan_bytes'], settings['min_length']
    unit = 1 if settings['encoding'] == 'ascii' else 2
    stream.seek(max(0, offset-unit))
    prefix = stream.read(min(unit, offset))
    stream.seek(offset)
    data = stream.read(min(budget, size-offset))
    atom = rb'[\x20-\x7e]' if unit == 1 else rb'[\x20-\x7e]\x00'
    pattern = re.compile(b'(?:' + atom + b'){' + str(minimum).encode() + b',}')
    rows, next_offset = [], offset + len(data)
    for match in pattern.finditer(data):
        if len(rows) == settings['limit']:
            next_offset = offset + match.start()
            break
        value = match.group()
        length = len(value) // unit
        rows.append({'offset': offset+match.start(), 'offset_hex': hex(offset+match.start()),
            'encoding': settings['encoding'], 'byte_length': len(value), 'character_count': length,
            'text': value[:settings['max_string_length']*unit].decode(settings['encoding']),
            'text_truncated': length > settings['max_string_length'],
            'continues_from_previous_window': match.start() == 0 and bool(re.fullmatch(atom, prefix)),
            'may_continue_in_next_window': len(data)-match.end() < unit and offset+len(data) < size})
    else:
        # Carry a too-short trailing candidate into the next page so a string
        # crossing the byte budget is not silently lost. A long string is emitted
        # as explicit fragments; a truncated preview still reports its full span.
        incomplete_unit = unit == 2 and data and 32 <= data[-1] <= 126
        tail_data = data[:-1] if incomplete_unit else data
        tail = re.search(b'(?:'+atom+b')+$', tail_data)
        if tail and len(tail.group()) < minimum*unit and offset+len(data) < size:
            next_offset = offset + tail.start()
        elif incomplete_unit and offset+len(data) < size:
            next_offset -= 1
    return {'records': rows, 'offset': offset, 'scanned_through': offset+len(data),
            'next_offset': next_offset, 'truncated': next_offset < size,
            'text_truncated': any(r['text_truncated'] for r in rows),
            'encoding_scope': 'Printable U+0020..U+007E; UTF-16LE accepts either byte alignment, not arbitrary Unicode.',
            'limitations': ['Strings are untrusted data; presence does not establish use or maliciousness.',
                            'Window-spanning strings can be explicitly marked fragments.']}


def main():
    source, settings = Path(sys.argv[1]), json.loads(sys.argv[2])
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
            raise ValueError('Inspection requires a regular artifact no larger than 64 MiB')
        if settings['operation'] == 'pe':
            result = pe_headers(stream.read(MAX_FILE+1))
        else:
            result = strings_page(stream, info.st_size, settings)
    json.dump(result, sys.stdout, ensure_ascii=True)


if __name__ == '__main__':
    main()
