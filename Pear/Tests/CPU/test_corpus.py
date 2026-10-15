# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject a falsely complete or altered CPU corpus without running guest code."""
import copy
from pathlib import Path
import tempfile
import unittest
from Pear.Tools.CPU import corpus as c


class CorpusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root/'unittests/ASM').mkdir(parents=True)
        self.path = 'unittests/ASM/one.asm'
        (self.root/self.path).write_bytes(b'%ifdef CONFIG\n{"RegData":{"RAX":"42"}}\n%endif\nmov rax,42\nhlt\n')
        rows, cfg = c.inventory(self.root)
        row = {k:v for k,v in rows[0].items() if k != 'config_error'}
        self.sources = dict(version=1, fex=dict(repository='https://github.com/FEX-Emu/FEX',
            revision='a'*40, inventory_count=1, inventory_sha256=c.digest(c.encoded(rows)), files={}),
            reviews=[], selection_ids=['boundary','one'])
        self.manifest = dict(version=1, scope='cpu_corpus_contract',
            sources_sha256=c.digest(c.encoded(self.sources)), cases=[dict(id='one', **row,
                categories=['partial_register'], requirement='required', contract=c.contract(cfg[self.path]),
                masks=[dict(bits='0xffffffffffffffff', reason='Defined integer result')],
                setup=dict(scratch_address=0xe0000000, scratch_size=65536, mxcsr=0x1f80,
                    x87_control=0x37f, entry='zero_gprs_vectors_preserve_native_abi_owned_stack',
                    termination='capture_at_hlt_without_flag_changes'),
                reference='native_windows_x64_same_pe_unavailable')],
            boundaries=[dict(id='boundary', categories=sorted(c.CATEGORIES-{'partial_register'}),
                stage=3, source=None, expected='Declared boundary outcomes', status='unperformed')],
            unsupported=dict(i386='Not executed'))

    def assess(self):
        return c.assess(self.root, self.manifest, self.sources,
                        contract_root=self.root/'tests/cpu', boundary_root=self.root)

    def test_inventory_is_not_cpu_qualification(self):
        result = self.assess()
        self.assertTrue(result['inventory_valid'])
        self.assertFalse(result['cpu_qualified'])
        self.assertFalse(result['guest_execution'])
        self.assertEqual(result['reference_status'], 'unavailable')
        self.assertEqual(result['census_count'], sum(result['classification_counts'].values()))

    def test_altered_or_extra_source_breaks_inventory(self):
        p=self.root/self.path; original=p.read_bytes()
        for change in (b'\n;changed',b'\nmov rbx,1'):
            p.write_bytes(original+change)
            with self.assertRaisesRegex(c.Error,'inventory_changed'): self.assess()
        p.write_bytes(original)
        (p.parent/'extra.asm').write_bytes(original)
        with self.assertRaisesRegex(c.Error,'inventory_changed'): self.assess()

    def test_incomplete_census_is_rejected(self):
        self.sources['fex']['inventory_count']=2
        self.manifest['sources_sha256']=c.digest(c.encoded(self.sources))
        with self.assertRaisesRegex(c.Error,'inventory_changed'): self.assess()

    def test_duplicates_and_missing_selected_cases_are_rejected(self):
        self.manifest['cases'].append(copy.deepcopy(self.manifest['cases'][0]))
        with self.assertRaisesRegex(c.Error,'duplicate_case'): self.assess()
        self.manifest['cases'].pop()
        self.sources['selection_ids'].append('missing')
        self.manifest['sources_sha256']=c.digest(c.encoded(self.sources))
        with self.assertRaisesRegex(c.Error,'missing_selected_case'): self.assess()

    def test_expected_values_cannot_be_replaced_with_candidate_output(self):
        self.manifest['cases'][0]['contract']['expectations'][0]['value']='0x0000000000000000'
        with self.assertRaisesRegex(c.Error,'case_contract_changed'): self.assess()

    def test_empty_expectations_and_masks_are_rejected(self):
        with self.assertRaisesRegex(c.Error,'empty_expectations'): c.contract({'RegData':{}})
        self.manifest['cases'][0]['masks'][0]['bits']='0x0'
        with self.assertRaisesRegex(c.Error,'empty_mask'): self.assess()
        self.manifest['cases'][0]['masks']=[]
        with self.assertRaisesRegex(c.Error,'missing_masks'): self.assess()

    def test_unknown_fields_and_tso_override_are_not_ignored(self):
        with self.assertRaisesRegex(c.Error,'unsupported_config_key'):
            c.contract({'RegData':{'RAX':'1'}, 'UnimplementedSetup':{}})
        for env in ({'FEX_TSOENABLED':'0'},{'FEX_HOSTFEATURES':'disablesve'}):
            with self.assertRaisesRegex(c.Error,'conflicting_environment'):
                c.contract({'RegData':{'RAX':'1'},'Env':env})
        self.manifest['passed']=True
        with self.assertRaisesRegex(c.Error,'manifest_fields'): self.assess()

    def test_vector_upper_lanes_are_retained_and_width_requires_feature(self):
        cfg={'RegData':{'XMM0':['1','2','3','4']},'HostFeatures':['AVX']}
        result=c.contract(cfg)
        self.assertEqual([e['lane'] for e in result['expectations']],[0,1,2,3])
        self.assertEqual(result['features'],['AVX'])
        del cfg['HostFeatures']
        with self.assertRaisesRegex(c.Error,'register_width'): c.contract(cfg)

    def test_memory_initialization_needs_real_nonoverlapping_regions(self):
        cfg={'RegData':{'RAX':'1'},'MemoryRegions':{'0x10000000':'4096'},'MemoryData':{'0x10000000':'AA BB'}}
        self.assertEqual(c.contract(cfg)['initial_memory'][0]['bytes'],'aabb')
        cfg['MemoryData']={'0x10000fff':'AA BB'}
        with self.assertRaisesRegex(c.Error,'memory_data_outside_region'): c.contract(cfg)
        cfg['MemoryRegions']={'0x10000000':'8192','0x10001000':'4096'}
        with self.assertRaisesRegex(c.Error,'memory_region_overlap'): c.contract(cfg)

    def test_duplicate_json_key_is_never_silently_last_value_wins(self):
        raw=b'%ifdef CONFIG\n{"RegData":{"RAX":"1","RAX":"2"}}\n%endif\nhlt\n'
        with self.assertRaisesRegex(c.Error,'duplicate_json_key'): c.config(raw)
        (self.root/self.path).write_bytes(raw)
        rows,cfg=c.inventory(self.root)
        self.assertEqual(rows[0]['config_error'],'duplicate_json_key')
        self.assertIsNone(cfg[self.path])

    def test_private_or_foreign_boundary_sources_are_not_followed(self):
        outside=self.root/'outside';outside.write_text('private')
        link=self.root/'link';link.symlink_to(outside)
        self.manifest['boundaries'][0]['source']=dict(path='link',sha256=c.digest(b'private'))
        with self.assertRaises(OSError): self.assess()
        self.manifest['boundaries'][0]['source']=dict(path='../outside',sha256=c.digest(b'private'))
        with self.assertRaisesRegex(c.Error,'unsafe_path'): self.assess()

    def test_unperformed_reference_or_boundary_cannot_be_promoted(self):
        self.manifest['cases'][0]['reference']='passed'
        with self.assertRaisesRegex(c.Error,'reference_not_observed'): self.assess()
        self.manifest['cases'][0]['reference']='native_windows_x64_same_pe_unavailable'
        self.manifest['boundaries'][0]['status']='passed'
        with self.assertRaisesRegex(c.Error,'boundary_scope'): self.assess()

    def test_retained_upstream_notice_must_match_reviewed_source(self):
        notice=b'MIT fixture notice'
        (self.root/'LICENSE').write_bytes(notice)
        target=self.root/'tests/cpu/LICENSES/FEX-MIT.txt'
        target.parent.mkdir(parents=True)
        target.write_bytes(notice)
        self.sources['fex']['files']['LICENSE']=c.digest(notice)
        self.manifest['sources_sha256']=c.digest(c.encoded(self.sources))
        self.assess()
        target.write_text('changed')
        with self.assertRaisesRegex(c.Error,'retained_notice_changed'): self.assess()

    def test_missing_required_category_is_rejected(self):
        self.manifest['boundaries'][0]['categories'].remove('ordering')
        with self.assertRaisesRegex(c.Error,'missing_required_category'): self.assess()


if __name__ == '__main__':
    unittest.main()
