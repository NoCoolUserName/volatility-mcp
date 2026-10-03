"""Synthetic-data checks for the additive XP plugin; never reads memory images."""
from datetime import datetime, timezone
import hashlib
import ipaddress
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

try:
    from volatility3.framework import contexts, exceptions, interfaces
except ImportError:
    raise unittest.SkipTest("Optional addon tests require the separate official Volatility environment")
from volatility3.framework.layers import physical, scanners
from volatility3.framework.symbols import intermed

from volatility_mcp.plugins.xpnet import XpNetScan

SYMBOLS = Path(__file__).resolve().parent / "fixtures/pool_header.json"
SNAPSHOT = datetime(2011, 6, 3, tzinfo=timezone.utc)


def allocation(tag=b"TCPT", pool_type=1, index=0, size=None, pid=1260, when=None):
    size = size or (0x198 if tag == b"TCPT" else 0x168)
    data = bytearray(size)
    struct.pack_into("<HH", data, 0, index << 9, (pool_type << 9) | (size // 8))
    data[4:8] = tag
    struct.pack_into("<I", data, 8, 0x81234560)
    if tag == b"TCPT":
        data[8 + 0xC:8 + 0x10] = ipaddress.IPv4Address("192.0.2.10").packed
        data[8 + 0x10:8 + 0x14] = ipaddress.IPv4Address("198.51.100.20").packed
        struct.pack_into(">HH", data, 8 + 0x14, 443, 1037)
        struct.pack_into("<I", data, 8 + 0x18, pid)
    elif size >= 0x168:
        data[8 + 0x2C:8 + 0x30] = ipaddress.IPv4Address("127.0.0.1").packed
        struct.pack_into(">H", data, 8 + 0x30, 53)
        struct.pack_into("<H", data, 8 + 0x32, 17)
        struct.pack_into("<I", data, 8 + 0x148, pid)
        when = when or datetime(2011, 6, 2, tzinfo=timezone.utc)
        ticks = int((when - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds()) * 10000000
        struct.pack_into("<Q", data, 8 + 0x158, ticks)
    return bytes(data)


class RecordingFile(interfaces.plugins.FileHandlerInterface):
    saved = {}

    def __init__(self, filename):
        super().__init__(filename)
        self.buffer = bytearray()

    def write(self, data):
        self.buffer.extend(data)
        return len(data)

    def close(self):
        if not self.closed:
            self.saved[self.preferred_filename] = bytes(self.buffer)
        super().close()


class XpNetTests(unittest.TestCase):
    def context(self, data, layer_type=physical.BufferDataLayer):
        context = contexts.Context()
        table = intermed.IntermediateSymbolTable(
            context, "symbols.test", "nttest", SYMBOLS.as_uri(), validate=True,
        )
        context.symbol_space.append(table)
        layer = layer_type(context, "layers.test", "physical", data, metadata={"architecture": "Intel32"})
        context.layers.add_layer(layer)
        kernel = context.module("nttest", "physical", 0)
        return context, kernel, layer

    def candidate(self, raw, pool=8, tag=None):
        context, kernel, layer = self.context(b"\0" * pool + raw)
        return XpNetScan._read_candidate(kernel, layer, pool + 4, tag or raw[4:8], SNAPSHOT)

    def test_typed_header_and_tcp_fields(self):
        raw = allocation(index=3)
        result = self.candidate(raw)
        self.assertEqual((result["PoolOffset"], result["ObjectOffset"], result["PoolIndex"]), (8, 16, 3))
        self.assertEqual((result["LocalIP"], result["LocalPort"], result["RemoteIP"], result["RemotePort"]),
                         ("198.51.100.20", 1037, "192.0.2.10", 443))
        self.assertEqual((result["Protocol"], result["PID"], result["NextVirtual"]), (6, 1260, 0x81234560))
        self.assertEqual(result["RawAllocationSHA256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result["RawAllocation"], raw)

    def test_socket_fields_and_timestamp(self):
        result = self.candidate(allocation(b"TCPA"))
        self.assertEqual((result["LocalIP"], result["LocalPort"], result["Protocol"]), ("127.0.0.1", 53, 17))
        self.assertEqual(result["CreatedUTC"], datetime(2011, 6, 2, tzinfo=timezone.utc))
        self.assertIsNone(result["RemoteIP"])

    def test_free_allocation_is_candidate_not_active(self):
        self.assertEqual(self.candidate(allocation(pool_type=0))["AllocationState"], "free")
        self.assertIn("current membership", XpNetScan.CAUTION)

    def test_paged_pool_and_high_index_rejected(self):
        self.assertIsNone(self.candidate(allocation(pool_type=2)))
        self.assertIsNone(self.candidate(allocation(index=5)))

    def test_small_socket_allocation_does_not_read_outside_it(self):
        self.assertIsNone(self.candidate(allocation(b"TCPA", size=0x160)))

    def test_truncated_allocation_rejected(self):
        self.assertIsNone(self.candidate(allocation()[:-1]))

    def test_unaligned_and_negative_headers_rejected(self):
        self.assertIsNone(self.candidate(allocation(), pool=1))
        context, kernel, layer = self.context(b"TCPT\0\0\0\0")
        self.assertIsNone(XpNetScan._read_candidate(kernel, layer, 0, b"TCPT", SNAPSHOT))

    def test_short_or_changed_tag_rejected(self):
        self.assertIsNone(self.candidate(b"\0\0\0\0TCPT"[:-1]))
        self.assertIsNone(self.candidate(allocation(), tag=b"TCPA"))

    def test_invalid_socket_time_rejected(self):
        for ticks in (0, 0xFFFFFFFFFFFFFFFF):
            raw = bytearray(allocation(b"TCPA"))
            struct.pack_into("<Q", raw, 8 + 0x158, ticks)
            self.assertIsNone(self.candidate(bytes(raw)))

    def test_future_time_and_unknown_pid_are_cautions(self):
        result = self.candidate(allocation(b"TCPA", pid=0, when=datetime(2011, 6, 4, tzinfo=timezone.utc)))
        self.assertIn("after snapshot", result["SanityNotes"])
        self.assertIn("zero PID", result["SanityNotes"])

    def test_missing_allocation_read_is_not_padded(self):
        class HoleLayer(physical.BufferDataLayer):
            def read(self, address, length, pad=False):
                if length > 8:
                    self.assert_not_padded = not pad
                    raise exceptions.InvalidAddressException(self.name, address, "synthetic hole")
                return super().read(address, length, pad)
        context, kernel, layer = self.context(b"\0" * 8 + allocation(), HoleLayer)
        self.assertIsNone(XpNetScan._read_candidate(kernel, layer, 12, b"TCPT", SNAPSHOT))
        self.assertTrue(layer.assert_not_padded)

    def test_framework_chunk_split_and_overlap_do_not_duplicate_tags(self):
        context, kernel, layer = self.context(b"\0" * 6 + b"TCPT" + b"\0" * 4 + b"TCPA" + b"\0" * 4)
        scanner = scanners.MultiStringScanner([b"TCPT", b"TCPA"])
        scanner.chunk_size, scanner.overlap = 8, 4
        hits = list(layer.scan(context, scanner, sections=[(0, layer.maximum_address + 1)]))
        self.assertEqual(hits, [(6, b"TCPT"), (14, b"TCPA")])

    def test_supported_identity_and_actionable_rejection(self):
        XpNetScan._validate_identity(5, 1, 32, False)
        for identity in ((5, 2, 32, False), (6, 1, 32, False), (5, 1, 64, True)):
            with self.assertRaisesRegex(ValueError, "only Windows XP 5.1 x86"):
                XpNetScan._validate_identity(*identity)

    def plugin(self, pid=None, dump=False):
        raw1, raw2 = allocation(pid=856), allocation(b"TCPA", pid=1260)
        context, kernel, layer = self.context(b"\0" * 8 + raw1 + raw2)
        context.config["plugins.test.kernel"] = kernel.name
        context.config["plugins.test.pid"] = pid
        context.config["plugins.test.dump"] = dump
        return XpNetScan(context, "plugins.test"), kernel, layer, raw1, raw2

    def test_pid_filter_and_default_dump_disabled(self):
        plugin, kernel, layer, _, _ = self.plugin(pid=[856])
        rows = list(plugin._generator(kernel, layer, SNAPSHOT))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1][13], 856)
        self.assertEqual(rows[0][1][19], "Disabled")

    def test_dump_uses_only_framework_handler_and_exact_bytes(self):
        RecordingFile.saved = {}
        plugin, kernel, layer, raw1, raw2 = self.plugin(dump=True)
        plugin.set_open_method(RecordingFile)
        rows = list(plugin._generator(kernel, layer, SNAPSHOT))
        self.assertEqual(len(rows), 2)
        self.assertEqual(RecordingFile.saved, {"xpnet-TCPT-00000008.bin": raw1, "xpnet-TCPA-000001a0.bin": raw2})
        self.assertIn("current membership", rows[0][1][-1])

    def test_real_treegrid_accepts_all_row_types(self):
        plugin, kernel, layer, _, _ = self.plugin()
        with patch.object(plugin, "_scan_context", return_value=(kernel, layer, SNAPSHOT)):
            grid = plugin.run()
        collected = []
        grid.populate(lambda node, _: collected.append(list(node.values)))
        self.assertEqual(len(collected), 2)
        self.assertEqual(collected[0][13], 856)


if __name__ == "__main__":
    unittest.main(verbosity=2)
