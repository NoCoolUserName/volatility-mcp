"""Synthetic first-batch checks under the configured analyzer Python.

No image, case, symbol download, executable payload or recovered URL is used.
Run: /path/to/analyzer/bin/python tests/addon_first_batch_smoke.py -v
"""
import contextlib
import hashlib
import io
import json
import struct
import sys
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch

# Deny network and subprocess creation before importing the plugins, too.
DENY = contextlib.ExitStack()
for target in ('socket.socket.connect', 'socket.create_connection', 'socket.getaddrinfo',
               'urllib.request.urlopen', 'subprocess.Popen'):
    DENY.enter_context(patch(target, side_effect=AssertionError('Offline fixture boundary: ' + target)))
from volatility3 import framework, plugins
from volatility3.framework import contexts, exceptions, renderers
from volatility3.framework.interfaces.configuration import HierarchicalDict
from volatility3.cli.text_renderer import JsonRenderer
FAILURES = framework.import_files(plugins, True)
from volatility3.plugins.windows import cobaltstrike as cs, richheader as rh, zoneid3 as zi, pte_resolve as pr, ptenum, pslist, vadyarascan, info


class BytesLayer:
    def __init__(self, data, base=0):
        self.data, self.base, self.reads = data, base, []

    def read(self, offset, length, pad=False):
        self.reads.append((offset, length, pad))
        if offset < self.base or offset + length > self.base + len(self.data):
            raise exceptions.InvalidAddressException('synthetic', offset)
        return self.data[offset-self.base:offset-self.base+length]


def instance(cls, values=None, layer=None):
    obj = object.__new__(cls)
    obj._config_path = 'fixture'
    obj._context = NS(config=HierarchicalDict(), layers={'memory':layer} if layer else {},
                      modules={'kernel':NS(layer_name='memory',symbol_table_name='symbols')})
    obj._context.config['fixture.kernel'] = 'kernel'
    obj._context.config['fixture.primary'] = 'memory'
    for name, value in (values or {}).items(): obj._context.config['fixture.'+name] = value
    return obj


def proc():
    return NS(UniqueProcessId=123, ImageFileName=[83,89,78,0],
              add_process_layer=lambda: 'memory', get_peb=lambda: NS(ImageBaseAddress=0),
              vol=NS(offset=4096), get_vad_root=lambda:NS(traverse=lambda: iter(())))


def render(grid):
    output = io.StringIO()
    with contextlib.redirect_stdout(output): JsonRenderer().render(grid)
    return json.loads(output.getvalue())


def field(number, kind, data):
    return struct.pack('>HHH',number,kind,len(data))+data


def cobalt(key=0x2e, tail=None):
    data = field(1,1,b'\0\x08') + field(2,1,struct.pack('>H',443))
    data += field(3,2,struct.pack('>I',60000))
    data += field(8,3,b'example.invalid,/synthetic\0')
    data += b'\0\0' if tail is None else tail
    return bytes(b ^ key for b in data)


def rich():
    data=bytearray(256); data[:2]=b'MZ'; struct.pack_into('<I',data,60,256)
    decoded=b'DanS'+b'\0'*12+struct.pack('<II',0x01020304,7)
    key=b'\x11\x22\x33\x44'
    data[64:88]=bytes(v ^ key[i%4] for i,v in enumerate(decoded))
    data[88:96]=b'Rich'+key
    return bytes(data), key, hashlib.md5(decoded, usedforsecurity=False).hexdigest()


class FirstBatchTests(unittest.TestCase):
    def setUp(self):
        # Synthetic process handles are not Volatility Array objects. Check
        # the real utility signature while isolating this unrelated conversion.
        self.conversion = patch('volatility3.framework.objects.utility.array_to_string', autospec=True, return_value='SYN')
        self.conversion.start()
        self.addCleanup(self.conversion.stop)

    def test_imports_and_current_requirement_versions(self):
        self.assertFalse(FAILURES)
        for cls in (cs.CobaltStrike, rh.RichHeader, zi.ZoneID3, pr.PteResolve):
            self.assertEqual(cls._required_framework_version[0], 2)
            for req in cls.get_requirements():
                if type(req).__name__ in {'PluginRequirement','VersionRequirement'}:
                    self.assertFalse(req.unsatisfied(contexts.Context(),'synthetic'), (cls,req.name))
        reqs={r.name:r for r in zi.ZoneID3.get_requirements()}
        self.assertFalse(reqs['start'].optional); self.assertFalse(reqs['length'].optional)
        self.assertNotIn('subsec_pte', {r.name for r in pr.PteResolve.get_requirements()})
        self.assertEqual(next(r for r in pr.PteResolve.get_requirements() if r.name=='kernel').requirements['layer_name'].architectures,['Intel64'])

    def test_cobalt_both_encodings_and_missing_fields(self):
        for key in (0x2e,0x69):
            parsed=cs.CobaltStrike.parse_result('cobaltstrike_config',cobalt(key))
            self.assertEqual(parsed['port'],443); self.assertEqual(parsed['sleeptime'],60000)
            self.assertEqual(parsed['server,get-uri'],'example.invalid,/synthetic')
            self.assertNotIn('jitter',parsed)

    def test_cobalt_malformed_configs_fail(self):
        invalid=[b'',b'wrong'*20,cobalt(tail=b''),cobalt(tail=field(2,1,b'\0P')+b'\0\0'),
                 cobalt(tail=field(5,2,b'\0')+b'\0\0'),cobalt(tail=field(10,3,b'\xff')+b'\0\0'),
                 cobalt(tail=field(5,3,b'wrong type')+b'\0\0'),b'x'*4097]
        for data in invalid:
            with self.subTest(data=data[:16]), self.assertRaises((ValueError,UnicodeError)):
                cs.CobaltStrike.parse_result('cobaltstrike_config',data)

    def test_cobalt_yara_chunk_boundary_json_and_read_bounds(self):
        offset=65530; data=b'\0'*offset+cobalt()+b'\0'*4096
        layer=BytesLayer(data); obj=instance(cs.CobaltStrike,{'pid':[123]},layer)
        with patch.object(pslist.PsList,'list_processes',autospec=True,return_value=iter([proc()])), \
             patch.object(vadyarascan.VadYaraScan,'get_vad_maps',autospec=True,return_value=[(0,len(data))]):
            rows=render(obj.run())
        self.assertEqual(len(rows),1); self.assertEqual(rows[0]['Offset'],hex(offset))
        self.assertEqual(rows[0]['Layer'],'memory'); self.assertEqual(rows[0]['Port'],443)
        self.assertIsNone(rows[0]['Jitter'])
        self.assertTrue(all(n<=65536 and not pad for _,n,pad in layer.reads))
        self.assertLessEqual(sum(n for _,n,_ in layer.reads),len(data)+4096)

    def test_cobalt_empty_and_limits(self):
        obj=instance(cs.CobaltStrike,{},BytesLayer(b'\0'*100))
        with patch.object(vadyarascan.VadYaraScan,'get_vad_maps',return_value=[(0,100)]):
            self.assertEqual(list(obj._generator([proc()])),[])
            obj.config['max-scan-bytes']=99
            with self.assertRaisesRegex(ValueError,'byte limit'): list(obj._generator([proc()]))
        obj.config['max-processes']=1
        with self.assertRaisesRegex(ValueError,'Process limit'): list(obj._generator([proc(),proc()]))

    def test_cobalt_result_limit(self):
        data=cobalt()+b'\0'*4096+cobalt()+b'\0'*4096
        obj=instance(cs.CobaltStrike,{'max-results':1},BytesLayer(data))
        with patch.object(vadyarascan.VadYaraScan,'get_vad_maps',return_value=[(0,len(data))]):
            with self.assertRaisesRegex(ValueError,'Result limit'): list(obj._generator([proc()]))

    def test_rich_known_hash_and_json_provenance(self):
        data,key,digest=rich()
        self.assertEqual(rh.RichHeader.parse_result(data),(key,digest))
        layer=BytesLayer(data);obj=instance(rh.RichHeader,{},layer)
        with patch.object(pslist.PsList,'list_processes',autospec=True,return_value=iter([proc()])):
            rows=render(obj.run())
        self.assertEqual(rows[0]['Rich Header Hash'],digest)
        self.assertEqual(rows[0]['RichOffset'],'0x58');self.assertEqual(rows[0]['ImageBase'],'0x0')
        self.assertEqual(layer.reads,[(0,64,False),(0,256,False)])

    def test_rich_absent_versus_malformed(self):
        blank=bytearray(128);blank[:2]=b'MZ'
        self.assertEqual(rh.RichHeader.parse_result(bytes(blank)),(None,None))
        data,_,_=rich()
        bad=bytearray(data);bad[68]^=1
        for value in (b'bad',bytes(bad),data[:93],b'MZ'+b'\0'*65535):
            with self.assertRaises(ValueError): rh.RichHeader.parse_result(value)

    def test_rich_bad_dos_size_and_missing_peb(self):
        data=bytearray(rich()[0]); struct.pack_into('<I',data,60,65537)
        obj=instance(rh.RichHeader,{},BytesLayer(data))
        with patch.object(pslist.PsList,'list_processes',return_value=iter([proc()])):
            with self.assertRaisesRegex(ValueError,'offset'): render(obj.run())
        p=proc();p.get_peb=lambda:None
        with patch.object(pslist.PsList,'list_processes',return_value=iter([p])):
            with self.assertRaisesRegex(ValueError,'PEB unavailable'): render(obj.run())

    def test_zone_record_boundaries_utf8_and_no_url(self):
        header=b'[ZoneTransfer]\r\nZoneId=3\r\n'
        self.assertEqual(zi.ZoneID3.parse_record(header),{})
        self.assertEqual(zi.ZoneID3.parse_record(header+b'\0HostUrl=wrong\r\n'),{})
        self.assertEqual(zi.ZoneID3.parse_record(header+header+b'HostUrl=wrong\r\n'),{})
        self.assertEqual(zi.ZoneID3.parse_record(header+b'HostUrl=https://example.invalid/a\r\n')[b'HostUrl'],'https://example.invalid/a')
        for data in (b'[ZoneTransfer]\r\nZoneId=3', header+b'HostUrl=unterminated',header+b'HostUrl=\xff\r\n',b'x'*1025):
            with self.assertRaises((ValueError,UnicodeError)): zi.ZoneID3.parse_record(data)

    def test_zone_real_yara_offset_chunk_boundary_json(self):
        offset=65530;record=b'[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.invalid/fixture\r\n\0'
        data=b'\0'*offset+record+b'\0'*1024
        layer=BytesLayer(data);obj=instance(zi.ZoneID3,{'start':0,'length':len(data)},layer)
        rows=render(obj.run())
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]['Offset'],hex(offset))
        self.assertEqual(rows[0]['Layer'],'memory');self.assertEqual(rows[0]['BytesRead'],1024)
        self.assertEqual(rows[0]['Host URL'],'https://example.invalid/fixture')
        self.assertIsNone(rows[0]['Referrer URL'])
        self.assertLessEqual(sum(n for _,n,_ in layer.reads),len(data)+1024)

    def test_zone_empty_required_arguments_and_bounds(self):
        obj=instance(zi.ZoneID3,{},BytesLayer(b'\0'*64))
        with self.assertRaises(KeyError): render(obj.run())
        obj.config['start']=0;obj.config['length']=64
        self.assertEqual(render(obj.run()),[])
        for name,value in [('length',0),('length',67108865),('start',-1),('start',2**64)]:
            obj.config['length']=64;obj.config['start']=0;obj.config[name]=value
            with self.assertRaises(ValueError): render(obj.run())

    def test_zone_truncated_header_is_error_in_json_renderer(self):
        data=b'[ZoneTransfer]\r\nZoneId=3'
        obj=instance(zi.ZoneID3,{'start':0,'length':len(data)},BytesLayer(data))
        output=io.StringIO()
        with contextlib.redirect_stdout(output),self.assertRaises(ValueError): JsonRenderer().render(obj.run())
        self.assertNotEqual(output.getvalue().strip(),'[]')

    def test_strict_read_and_scan_errors_never_empty(self):
        for module in (cs,rh,zi,pr):
            with self.assertRaises(ValueError):module._read(BytesLayer(b'123'),0,65537)
            with self.assertRaises(exceptions.InvalidAddressException):module._read(BytesLayer(b'123'),0,4)
            with self.assertRaises(ValueError):module._read(NS(read=lambda *a,**k:b''),0,4)
        with self.assertRaisesRegex(RuntimeError,'scanner failed'):
            list(cs._scan(BytesLayer(b'a'),[(0,1)],lambda *a: (_ for _ in ()).throw(RuntimeError('scanner failed')),[1]))
        with self.assertRaises(exceptions.InvalidAddressException):
            list(zi._scan(BytesLayer(b'a'),[(0,2)],lambda *a: iter(()),[2]))

    def test_pte_selector_contract_and_current_pslist_signature(self):
        for values in ({},{'vaddr':1},{'pte_value':-1},{'pte_value':2**64},{'pte_paddr':7},
                       {'pte_value':0,'vaddr':4096},{'vaddr':4096,'pid':[1,2]}):
            with self.subTest(values=values),self.assertRaises(ValueError):instance(pr.PteResolve,values).run()
        for mode in ('vaddr','pte_vaddr','pte_paddr','pte_value'):
            obj=instance(pr.PteResolve,{mode:4096,'pid':[123]})
            with patch.object(pslist.PsList,'list_processes',autospec=True,return_value=iter(())), \
                 patch.object(pr.PteResolve,'_generator',return_value=iter(())):
                self.assertEqual(render(obj.run()),[])

    def test_pte_output_and_failed_or_unknown_resolution(self):
        obj=instance(pr.PteResolve,{'pte_value':1})
        obj._initialize_internals=lambda:None
        result=NS(pid=0,proc=None,state='HARD',length=4096,get_full_string_repr=lambda:'Synthetic active PTE')
        obj.resolve_pte_by_pte_value=lambda value:result
        with patch.object(pslist.PsList,'list_processes',autospec=True,return_value=iter(())):
            rows=render(obj.run())
        self.assertEqual(rows[0]['PID'],0);self.assertEqual(rows[0]['InputKind'],'pte_value')
        self.assertEqual(rows[0]['InputValue'],'0x1')
        for result_value in (None,NS(state='Undetermined',length=4096),NS(state='HARD',length=0x200000)):
            obj.resolve_pte_by_pte_value=lambda value:result_value
            with self.assertRaises(ValueError):list(obj._generator(iter(())))
        result.get_full_string_repr=lambda:'x'*65537
        obj.resolve_pte_by_pte_value=lambda value:result
        with self.assertRaisesRegex(ValueError,'output exceeds'):list(obj._generator(iter(())))

    def test_pte_selected_pid_must_exist(self):
        obj=instance(pr.PteResolve,{'vaddr':4096,'pid':[123]})
        with self.assertRaisesRegex(ValueError,'PID is unavailable'):list(obj._generator(iter(())))

    def test_pte_single_pfn_read_not_whole_database(self):
        layer=BytesLayer(b'A'*96,base=4096)
        obj=instance(pr.PteResolve,{},layer);obj.kernel_layer=layer
        obj._hpp=1;obj._mmpfn_entry_size=48;obj.mmpfn_db=NS(vol=NS(offset=4096))
        obj._ensure_mmpfn_db_raw();self.assertFalse(layer.reads)
        self.assertEqual(obj._get_mmpfn_entry_raw(1),b'A'*48)
        self.assertEqual(layer.reads,[(4144,48,False)])
        with self.assertRaises(ValueError):obj._get_mmpfn_entry_raw(2)

    def test_pte_budget_strict_padding_restoration_and_swallowed_errors(self):
        layer=BytesLayer(b'A'*65536); original=layer.read
        context=NS(layers={'memory':layer})
        with pr._ReadBudget(context) as budget:
            self.assertEqual(layer.read(0,1,pad=True),b'A')
            budget.remaining=1
            with self.assertRaises(ValueError):layer.read(0,2)
            self.assertTrue(budget.failed)
        self.assertEqual(layer.read,original);self.assertNotIn('read',layer.__dict__)
        self.assertFalse(layer.reads[0][2])
        obj=instance(pr.PteResolve,{'pte_value':1},layer)
        obj._initialize_internals=lambda:None
        def swallowed(value):
            try:layer.read(0,65537)
            except ValueError:pass
            return NS(pid=0,proc=None,state='HARD',length=4096,get_full_string_repr=lambda:'misleading success')
        obj.resolve_pte_by_pte_value=swallowed
        with self.assertRaisesRegex(ValueError,'PTE read failed'):list(obj._generator(iter(())))
        self.assertEqual(layer.read,original)

    def test_pte_synthetic_hardware_and_transition_bit_decoding(self):
        # Exercise the real shared resolver with explicit synthetic bit layouts.
        # Symbol initialization/PFN corroboration are isolated, not claimed tested.
        obj=object.__new__(ptenum.PteEnumerator);ptenum.PteEnumerator.__init__(obj)
        obj.pid=0;obj._PAGE_SIZE=4096;obj._PAGE_BITS=12;obj._PAGE_BITS_MASK=4095
        obj._nx_mask=1<<63;obj._page_size_mask=128;obj._prototype_mask=1024;obj._transition_mask=2048
        obj._hard_pfn_start=obj._trans_pfn_start=12
        obj._hard_pfn_mask=obj._trans_pfn_mask=0x0000fffffffff000
        obj._trans_protection_start=5;obj._trans_protection_mask=0x3e0
        obj._executable_prots=[6];obj.phys_layer=BytesLayer(b'');obj._already_initialized=True
        obj._is_demand_zero_pte=lambda value:False
        obj._get_modified_page_characteristics=lambda pfn:{'has_proto_set':False,'orig_pte':0,'orig_pte_is_sub_ptr':False}
        for value,expected in ((0x12345001,'HARD'),(0x12345001|(1<<63),'HARD'),(0x12345000|2048|(6<<5),'TRANS')):
            result=obj.resolve_pte(0x400000,value,0x1000,zero_ret=False)
            self.assertEqual(result.phys_offset,0x12345000)
            self.assertEqual(result.state,expected)
            self.assertEqual(result.length,4096)
            self.assertEqual(result.is_executable,not bool(value & (1<<63)))


if __name__=='__main__':
    try: unittest.main()
    finally: DENY.close()
