"""Minimal synthetic PE header fixtures with inert bytes, never executable code."""
import struct


def synthetic_pe(plus=False, dll=False):
    data = bytearray(1024)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    optsize = 240 if plus else 224
    struct.pack_into('<HHIIIHH', data, 0x84, 0x8664 if plus else 0x14c, 1, 0, 0, 0,
                     optsize, 0x2022 if dll else 0x22)
    opt = 0x98
    struct.pack_into('<H', data, opt, 0x20b if plus else 0x10b)
    struct.pack_into('<I', data, opt+16, 0x1000)
    struct.pack_into('<Q' if plus else '<I', data, opt+(24 if plus else 28), 0x140000000 if plus else 0x400000)
    struct.pack_into('<II', data, opt+32, 0x1000, 0x200)
    struct.pack_into('<II', data, opt+56, 0x2000, 0x200)
    struct.pack_into('<H', data, opt+68, 3)
    struct.pack_into('<I', data, opt+(108 if plus else 92), 16)
    start = opt + optsize
    data[start:start+8] = b'.text\0\0\0'
    struct.pack_into('<IIII', data, start+8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into('<I', data, start+36, 0x60000020)
    data[0x210:0x21c] = b'HELLO_ASCII\0'
    wide = 'WORLD_WIDE'.encode('utf-16le')
    data[0x240:0x240+len(wide)] = wide
    odd = 'ODD_WIDE'.encode('utf-16le')
    data[0x281:0x281+len(odd)] = odd
    return bytes(data)
