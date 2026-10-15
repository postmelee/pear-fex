# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Original generator assertions and explicit-contract isolation checks."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from Pear.Tools.CPU import corpus, adapt, generate


class OriginalGeneratorTests(unittest.TestCase):
    def setUp(self):
        self.manifest=corpus.load_json(corpus.CONTRACT_ROOT/'corpus.json')

    def test_mapping_keeps_absolute_page_with_granular_reservation(self):
        c=next(c for c in self.manifest['cases'] if c['id']=='absolute-displacement')
        reserved,committed=generate.reservations(c)
        self.assertIn([0x7fff0000,0x80000000],reserved)
        self.assertIn(dict(address=0x7ffff000,size=4096),committed)

    def test_bad_capture_input_is_rejected(self):
        c=self.manifest['cases'][0]
        for body in ('nop','%include "other.asm"\nhlt'):
            with self.assertRaises(Exception):
                generate.assembly(c,('%ifdef CONFIG\n{}\n%endif\n'+body).encode())


class ExplicitSourceBindings(unittest.TestCase):
    def setUp(self):
        self.manifest=corpus.load_json(corpus.CONTRACT_ROOT/'corpus.json')
        self.case=next(c for c in self.manifest['cases'] if c['id']=='absolute-displacement')
        self.rules=adapt.rules()

    def test_explicit_adaptation_does_not_read_ambient_contract(self):
        with patch.object(adapt,'rules',side_effect=AssertionError('ambient rules')):
            changed=adapt.effective_case(self.case,self.rules)
            self.assertEqual(changed['contract']['regions'][0]['address'],
                             self.rules['cases'][self.case['id']]['effective_data_page'])
            self.assertEqual(changed['contract']['expectations'][:-1],
                             self.case['contract']['expectations'])
            self.assertEqual(changed['contract']['expectations'][-1],
                             self.rules['cases'][self.case['id']]['additional_expectation'])

    def test_explicit_empty_rules_never_fall_back_to_default_adaptation(self):
        rules={**self.rules,'cases':{}}
        with patch.object(adapt,'rules',side_effect=AssertionError('ambient rules')):
            self.assertIs(adapt.effective_case(self.case,rules),self.case)

    def test_changed_adaptation_source_is_refused(self):
        case=copy.deepcopy(self.case);case['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'adaptation_source_changed'):
            adapt.effective_case(case,self.rules)

    def test_contract_reader_rejects_duplicate_keys_and_symlink_leaves(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);path=root/'adaptations.json'
            path.write_text('{"cases":{},"cases":{}}')
            with self.assertRaisesRegex(corpus.Error,'duplicate_json_key'):adapt.rules(root)
            path.unlink();(root/'real.json').write_text('{"cases":{}}')
            path.symlink_to('real.json')
            with self.assertRaises(OSError):adapt.rules(root)

    def test_existing_output_and_aliased_parent_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();existing=root/'exists';existing.mkdir()
            with self.assertRaisesRegex(corpus.Error,'output_exists'):corpus.fresh_output(existing)
            alias=root/'alias';alias.symlink_to(root,target_is_directory=True)
            with self.assertRaisesRegex(corpus.Error,'output_parent_alias'):
                corpus.fresh_output(alias/'new')
            with self.assertRaisesRegex(corpus.Error,'cpu_root_alias'):
                corpus.canonical_root(alias)


if __name__=='__main__':unittest.main()
