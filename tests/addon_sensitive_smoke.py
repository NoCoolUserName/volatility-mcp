"""Synthetic secret-extraction contracts; no real credentials or images."""
import json
import struct
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
from addon_first_batch_smoke import BytesLayer, instance, proc, render
from volatility3.framework import contexts, exceptions
from volatility3.framework.layers.physical import BufferDataLayer
from volatility3.framework.symbols.intermed import IntermediateSymbolTable
from volatility3.plugins.windows import passwordmanagers as pm
from volatility3.plugins.linux import openssh_sessionkeys as ssh


class SensitiveTests(unittest.TestCase):
    def setUp(self):
        self.convert = patch('volatility3.framework.objects.utility.array_to_string', return_value='chrome.exe')
        self.convert.start(); self.addCleanup(self.convert.stop)

    def ssh_fixture(self, bits=64, layout='sshenc_61p2', malformed=None):
        context = contexts.Context()
        import volatility3
        schema_path = Path(volatility3.__file__).parent/'framework/symbols/linux'/('openssh'+str(bits)+'.json')
        # ResourceAccessor uses urlopen for file:// too. Permit only this pinned
        # local schema; network primitives remain denied before plugin imports.
        with patch('volatility3.framework.layers.resources.ResourceAccessor.open', return_value=schema_path.open('rb')):
            table = IntermediateSymbolTable.create(context, 'test', 'linux', 'openssh'+str(bits))
        import volatility3
        schema = json.loads((Path(volatility3.__file__).parent/'framework/symbols/linux'/('openssh'+str(bits)+'.json')).read_text())
        data = bytearray(3072)
        values = {'name':0x200,'cipher':0x280,'enabled':1,'key_len':16,'iv_len':16,'block_size':16,'key':0x300,'iv':0x340}
        values.update(malformed or {})
        for field, entry in schema['user_types'][layout]['fields'].items():
            fmt = '<Q' if entry['type']['kind']=='pointer' and bits==64 else '<I'
            struct.pack_into(fmt,data,0x100+entry['offset'],values[field])
        data[0x200:0x20b] = b'aes128-ctr\0'
        struct.pack_into('<Q' if bits==64 else '<I',data,0x280,0x200)
        # Assign exact-length synthetic values without resizing the memory buffer.
        data[0x300:0x310]=bytes(range(16));data[0x340:0x350]=bytes(range(16,32))
        layer=BufferDataLayer(context,'test.layer','memory',bytes(data));context.layers.add_layer(layer)
        task=NS(comm=[83,89,78,0],pid=123,mm=True,add_process_layer=lambda:'memory')
        extractor=ssh.SSHKeyExtractor(context,table,'memory',task,None)
        return extractor,context,table,task

    def test_required_arguments_versions_and_no_output_path(self):
        for cls in (pm.PasswordManager,ssh.SSHKeys):
            req={r.name:r for r in cls.get_requirements()}
            self.assertFalse(req['pid'].optional)
            self.assertNotIn('out',req)
            for requirement in req.values():
                if type(requirement).__name__=='VersionRequirement':
                    self.assertFalse(requirement.unsatisfied(contexts.Context(),'fixture'))
            with self.assertRaises(ValueError): instance(cls).run()
        self.assertFalse({r.name:r for r in ssh.SSHKeys.get_requirements()}['address'].optional)

    def test_password_strict_strings_no_debug_and_empty(self):
        value=b'{"unencryptedUsername":"synthetic\\u0040example.invalid","password","value":"synthetic\\\"value","tld":"example.invalid"}'
        with patch.object(pm.vollog,'debug',side_effect=AssertionError('No secret logging')):
            self.assertEqual(pm.PasswordManager.parse_result('lastpass_strcutc',value),('synthetic@example.invalid','synthetic"value','example.invalid'))
        self.assertEqual(pm.PasswordManager.parse_result('lastpass_strcutc',b'{}'),(None,None,None))
        for bad in (b'"unencryptedUsername":"unterminated',b'"unencryptedUsername":"\\x"',b'"unencryptedUsername":"\xff"',b'x'*4097):
            with self.assertRaises((ValueError,UnicodeError)):pm.PasswordManager.parse_result('lastpass_strcutc',bad)

    def test_password_real_yara_json_and_provenance(self):
        fragment=b'{"cmd":"save","unencryptedUsername":"synthetic","password","value":"fixture-only","tld":"example.invalid"}'
        layer=BytesLayer(b'\0'*32+fragment+b'\0'*64)
        plugin=instance(pm.PasswordManager,{'pid':123},layer)
        with patch.object(pm.pslist.PsList,'list_processes',autospec=True,return_value=[proc()]) as listing, patch.object(pm.vadyarascan.VadYaraScan,'get_vad_maps',return_value=[(0,len(layer.data))]):
            rows=render(plugin.run())
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]['Offset'],'0x20')
        self.assertEqual(rows[0]['Password'],'fixture-only');self.assertEqual(rows[0]['Layer'],'memory')
        self.assertIn('kernel_module_name',listing.call_args.kwargs)
        self.assertTrue(all(n<=65536 and not pad for _,n,pad in layer.reads))

    def test_password_missing_pid_scan_error_and_bounds(self):
        plugin=instance(pm.PasswordManager,{'pid':123},BytesLayer(b'\0'*64))
        with self.assertRaisesRegex(ValueError,'not found'):list(plugin._generator([]))
        with patch.object(pm.vadyarascan.VadYaraScan,'get_vad_maps',return_value=[(0,65)]), self.assertRaises(exceptions.InvalidAddressException):list(plugin._generator([proc()]))
        for key,value in [('max-scan-bytes',67108865),('max-results',1001)]:
            with self.assertRaises(ValueError):list(instance(pm.PasswordManager,{key:value})._generator([]))

    def test_ssh_real_isfs_both_bitness_and_layouts(self):
        for bits in (32,64):
            for layout in ('sshenc_61p1','sshenc_61p2'):
                with self.subTest(bits=bits,layout=layout):
                    extractor,context,_,_=self.ssh_fixture(bits,layout)
                    with ssh._ReadBudget(context) as budget:
                        candidate=extractor.probe_address(0x100)
                        self.assertIsNotNone(candidate)
                        key=extractor.construct_scraped_key(candidate,0x100)
                    self.assertFalse(budget.failed)
                    self.assertEqual(key.key,bytes(range(16)).hex())
                    self.assertEqual(key.iv,bytes(range(16,32)).hex())
                    self.assertNotIn(key.key,str(key))

    def test_ssh_malformed_and_unreadable_not_empty(self):
        for values in ({'key_len':999},{'iv_len':999},{'name':3584},{'key':3584},{'block_size':999,'iv_len':999}):
            extractor,context,_,_=self.ssh_fixture(malformed=values)
            with self.subTest(values=values),self.assertRaises((ValueError,exceptions.InvalidAddressException)):
                with ssh._ReadBudget(context):
                    candidate=extractor.probe_address(0x100)
                    extractor.construct_scraped_key(candidate,0x100)
        extractor,_,_,_=self.ssh_fixture()
        with self.assertRaises(ValueError):extractor.probe_address(0)
        with self.assertRaises(ValueError):list(extractor.extract())

    def test_ssh_empty_json_and_output_no_arbitrary_file(self):
        extractor,context,table,task=self.ssh_fixture()
        plugin=instance(ssh.SSHKeys,{'pid':123,'address':0x100})
        plugin._progress_callback=None
        plugin._context.layers=context.layers;plugin._context.symbol_space=context.symbol_space;plugin._context.object=context.object
        with patch.object(ssh.symbols,'symbol_table_is_64bit',return_value=True),patch.object(ssh.intermed.IntermediateSymbolTable,'create',return_value=table),patch.object(ssh.pslist.PsList,'list_tasks',autospec=True,return_value=[task]):
            rows=render(plugin.run())
        self.assertEqual(rows[0]['Address'],'0x100');self.assertEqual(rows[0]['Layer'],'memory')
        with self.assertRaises(ValueError):plugin.write_output_file('/forbidden',[])
        with patch.object(ssh,'_cstring',return_value='unsupported-cipher'):
            self.assertIsNone(extractor.probe_address(0x100))


if __name__=='__main__':unittest.main()
