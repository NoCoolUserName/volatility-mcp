"""Local Windows XP x86 network pool carving for Volatility 3.

This additive plugin is not an official Volatility NetScan implementation and
does not enumerate active network tables. TCPT/TCPA layouts and pool checks
follow these official, historical Volatility Foundation sources:
https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/overlays/windows/tcpip_vtypes.py#L18-L36
https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/connscan.py#L34-L45
https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/sockscan.py#L36-L49

The framework supplies the actual kernel's typed _POOL_HEADER and physical
memory layer. Allocation reads are bounded, unpadded, and never written back.
Only self.open() writes optional allocation dumps to framework-managed output.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import logging
import struct
from typing import Optional

from volatility3.framework import exceptions, interfaces, renderers, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import info

vollog = logging.getLogger(__name__)


class XpNetScan(interfaces.plugins.PluginInterface):
    """Locally carve XP x86 TCPT/TCPA pool candidates; activity is unknown."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)
    HEADER_SIZE = 8
    TAG_OFFSET = 4
    ALIGNMENT = 8
    # (minimum total allocation, minimum object bytes covering all fields)
    LAYOUTS = {b"TCPT": (0x198, 0x20), b"TCPA": (0x15C, 0x160)}
    CAUTION = (
        "Carved candidate; current membership, TCP state and traffic unknown; "
        "may be stale, damaged or false-positive; PID ownership/reuse requires corroboration"
    )

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Windows kernel with full typed symbols",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="info", component=info.Info, version=(2, 0, 0),
            ),
            requirements.ListRequirement(
                name="pid", description="Include only these decoded candidate PIDs",
                element_type=int, optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump", description="Save exact raw pool allocations to the configured output directory",
                default=False, optional=True,
            ),
        ]

    @staticmethod
    def _validate_identity(major: int, minor: int, bits: int, is_64bit: bool):
        if (major, minor, bits, is_64bit) != (5, 1, 32, False):
            raise ValueError(
                "xpnet.XpNetScan supports only Windows XP 5.1 x86; "
                f"identified NT {major}.{minor}, {bits}-bit layer, 64-bit symbols={is_64bit}. "
                "Run windows.info.Info and select a network plugin supporting that OS/architecture."
            )

    def _scan_context(self):
        kernel = self.context.modules[self.config["kernel"]]
        virtual = self.context.layers[kernel.layer_name]
        try:
            kuser = info.Info.get_kuser_structure(self.context, self.config["kernel"])
            self._validate_identity(
                int(kuser.NtMajorVersion), int(kuser.NtMinorVersion),
                getattr(virtual, "bits_per_register", 0),
                symbols.symbol_table_is_64bit(self.context, kernel.symbol_table_name),
            )
        except (exceptions.InvalidAddressException, exceptions.SymbolError, AttributeError) as exc:
            raise ValueError(
                "xpnet.XpNetScan cannot confirm Windows XP 5.1 x86 from the kernel. "
                "Run windows.info.Info and provide matching full typed kernel symbols."
            ) from exc
        try:
            header = kernel.get_type("_POOL_HEADER")
            if header.size != self.HEADER_SIZE or header.relative_child_offset("PoolTag") != self.TAG_OFFSET:
                raise ValueError("Unexpected _POOL_HEADER size/tag offset")
            for field in ("BlockSize", "PoolType", "PoolIndex"):
                header.relative_child_offset(field)
        except (exceptions.SymbolError, KeyError, ValueError) as exc:
            raise ValueError(
                "xpnet.XpNetScan requires the XP kernel's typed 8-byte _POOL_HEADER "
                "with PoolTag at +4 and BlockSize/PoolType/PoolIndex fields; use matching full typed symbols."
            ) from exc
        physical_name = virtual.config.get("memory_layer")
        if not physical_name or physical_name == kernel.layer_name or physical_name not in self.context.layers:
            raise ValueError(
                "xpnet.XpNetScan requires the Windows kernel layer's underlying physical memory layer; "
                "check image format and layer construction with windows.info.Info."
            )
        snapshot = None
        try:
            value = kuser.SystemTime.get_time()
            if isinstance(value, datetime) and value.tzinfo is not None:
                snapshot = value
        except (exceptions.InvalidAddressException, AttributeError, ValueError, OverflowError):
            pass
        return kernel, self.context.layers[physical_name], snapshot

    @classmethod
    def _decode_allocation(cls, raw: bytes, tag: bytes, snapshot: Optional[datetime]):
        """Decode bounded bytes, using offsets relative to the object after its header."""
        body = raw[cls.HEADER_SIZE:]
        if tag not in cls.LAYOUTS or len(body) < cls.LAYOUTS[tag][1]:
            return None
        notes = []
        result = {
            "NextVirtual": struct.unpack_from("<I", body, 0)[0],
            "RemoteIP": None, "RemotePort": None,
            "CreatedUTC": None, "CreateTimeFiletime": None,
        }
        if tag == b"TCPT":
            result.update(
                Kind="tcp_connection_candidate", Protocol=6,
                RemoteIP=str(ipaddress.IPv4Address(body[0xC:0x10])),
                LocalIP=str(ipaddress.IPv4Address(body[0x10:0x14])),
                RemotePort=struct.unpack_from(">H", body, 0x14)[0],
                LocalPort=struct.unpack_from(">H", body, 0x16)[0],
                PID=struct.unpack_from("<I", body, 0x18)[0],
            )
            if not result["RemotePort"] or not result["LocalPort"]:
                notes.append("Zero port; possible overwritten or residual object")
        else:
            filetime = struct.unpack_from("<Q", body, 0x158)[0]
            try:
                created = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=filetime // 10)
            except OverflowError:
                return None
            # Same conservative timestamp check used by the prior tested local carver.
            if created <= datetime(1970, 1, 1, tzinfo=timezone.utc):
                return None
            result.update(
                Kind="socket_candidate", LocalIP=str(ipaddress.IPv4Address(body[0x2C:0x30])),
                LocalPort=struct.unpack_from(">H", body, 0x30)[0],
                Protocol=struct.unpack_from("<H", body, 0x32)[0],
                PID=struct.unpack_from("<I", body, 0x148)[0],
                CreatedUTC=created, CreateTimeFiletime=filetime,
            )
            if snapshot is not None and created > snapshot:
                notes.append("Creation time after snapshot; do not treat as a reliable event")
            if snapshot is None:
                notes.append("Snapshot time unavailable; creation chronology not checked")
            if result["Protocol"] not in (1, 6, 17, 47):
                notes.append("Unusual protocol; check raw bytes and possible overwrite")
        if result["PID"] == 0 or result["PID"] > 65535:
            notes.append("Unusual/zero PID; ownership requires corroboration")
        result["SanityNotes"] = "; ".join(notes)
        return result

    @classmethod
    def _read_candidate(cls, kernel, physical, tag_offset, tag, snapshot):
        pool = tag_offset - cls.TAG_OFFSET
        if pool < physical.minimum_address or pool % cls.ALIGNMENT:
            return None
        if not physical.is_valid(pool, cls.HEADER_SIZE):
            return None
        try:
            header = kernel.object(
                "_POOL_HEADER", offset=pool, absolute=True,
                layer_name=physical.name, native_layer_name=kernel.layer_name,
            )
            size = int(header.BlockSize) * cls.ALIGNMENT
            pool_type, index = int(header.PoolType), int(header.PoolIndex)
            minimum, required = cls.LAYOUTS[tag]
            if size < max(minimum, cls.HEADER_SIZE + required) or index >= 5:
                return None
            if pool_type != 0 and pool_type % 2 != 1:
                return None
            # Never pad holes/truncated allocations or hash synthetic zero bytes.
            if not physical.is_valid(pool, size):
                return None
            raw = physical.read(pool, size, pad=False)
        except exceptions.InvalidAddressException:
            return None
        if len(raw) != size or raw[cls.TAG_OFFSET:cls.TAG_OFFSET + 4] != tag:
            return None
        result = cls._decode_allocation(raw, tag, snapshot)
        if result is None:
            return None
        result.update(
            PoolOffset=pool, ObjectOffset=pool + cls.HEADER_SIZE, Tag=tag.decode("ascii"),
            PoolType=pool_type, AllocationState="free" if pool_type == 0 else "nonpaged",
            PoolIndex=index, AllocationBytes=size, RawAllocationSHA256=hashlib.sha256(raw).hexdigest(),
            RawHeaderHex=raw[:cls.HEADER_SIZE].hex(), RawAllocation=raw,
        )
        return result

    def _generator(self, kernel, physical, snapshot):
        pid_filter = set(self.config.get("pid") or [])
        scanner = scanners.MultiStringScanner(list(self.LAYOUTS))
        # Framework overlap/chunk handling returns tags once, including split tags.
        sections = [(physical.minimum_address, physical.maximum_address - physical.minimum_address + 1)]
        for offset, tag in physical.scan(self.context, scanner, self._progress_callback, sections=sections):
            result = self._read_candidate(kernel, physical, offset, tag, snapshot)
            if result is None or (pid_filter and result["PID"] not in pid_filter):
                continue
            output = "Disabled"
            if self.config.get("dump", False):
                filename = f"xpnet-{result['Tag']}-{result['PoolOffset']:08x}.bin"
                try:
                    with self.open(filename) as stream:
                        stream.write(result["RawAllocation"])
                    output = stream.preferred_filename
                except OSError as exc:
                    raise OSError(
                        "xpnet.XpNetScan could not save its raw allocation through the framework; "
                        "check the configured output directory permissions and free space."
                    ) from exc
            absent = renderers.NotApplicableValue
            yield 0, (
                format_hints.Hex(result["PoolOffset"]), format_hints.Hex(result["ObjectOffset"]),
                result["Tag"], result["PoolType"], result["AllocationState"], result["PoolIndex"],
                result["AllocationBytes"], result["Kind"], result["LocalIP"], result["LocalPort"],
                result["RemoteIP"] if result["RemoteIP"] is not None else absent(),
                result["RemotePort"] if result["RemotePort"] is not None else absent(),
                result["Protocol"], result["PID"],
                result["CreatedUTC"] if result["CreatedUTC"] is not None else absent(),
                result["CreateTimeFiletime"] if result["CreateTimeFiletime"] is not None else absent(),
                format_hints.Hex(result["NextVirtual"]), result["RawAllocationSHA256"],
                result["RawHeaderHex"], output, result["SanityNotes"], self.CAUTION,
            )

    def run(self):
        kernel, physical, snapshot = self._scan_context()
        vollog.warning("Local XP physical pool carving: current membership, TCP state and traffic are unknown")
        return renderers.TreeGrid([
            ("PoolOffset(P)", format_hints.Hex), ("ObjectOffset(P)", format_hints.Hex),
            ("Tag", str), ("PoolType", int), ("AllocationState", str), ("PoolIndex", int),
            ("AllocationBytes", int), ("Kind", str), ("LocalIP", str), ("LocalPort", int),
            ("RemoteIP", str), ("RemotePort", int), ("Protocol", int), ("PID", int),
            ("CreatedUTC", datetime), ("CreateTimeFiletime", int), ("Next(V)", format_hints.Hex),
            ("RawAllocationSHA256", str), ("RawHeaderHex", str), ("File output", str),
            ("SanityNotes", str), ("Caution", str),
        ], self._generator(kernel, physical, snapshot))
