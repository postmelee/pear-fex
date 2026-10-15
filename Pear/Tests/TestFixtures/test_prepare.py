# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Source-preparation and refusal controls; no compiler or native process."""
import copy
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from Pear.Tools.TestFixtures import prepare as tool

FEX = Path(__file__).resolve().parents[3]
RECIPE = FEX / 'Pear/Tests/TestFixtures/selected-v1.json'


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / 'source'; self.source.mkdir()
        self.fixture = self.source / 'fixture.cpp'; self.fixture.write_bytes(b'original fixture\n')
        self.fixture.chmod(0o644)
        row = dict(root='fex', path='fixture.cpp', sha256=tool.digest(self.fixture.read_bytes()),
                   size_bytes=self.fixture.stat().st_size, mode='100644')
        self.recipe = dict(schema_version=1, kind='pear_fex_component_source_preparation',
            source_basis={}, policy={}, inputs={'fixture': row}, cases={'sample': dict(
                inputs=['fixture'], fixture='fixture', generator='copies_only',
                copies={'fixture.cpp': 'fixture'}, generated={'fixture.cpp': {k: row[k] for k in ('sha256','size_bytes')}},
                commands=[dict(id='future', argv_template=['{compiler}', 'fixture.cpp'], expected_exit=0)],
                native_input_gaps=['compiler and transitive headers absent'], oracle='original assertion', source_correspondence='synthetic input')})
        self.recipe_path = self.root / 'recipe.json'
        self.write_recipe()

    def write_recipe(self):
        self.recipe_path.write_text(json.dumps(self.recipe))

    def invoke(self, **kwargs):
        return tool.prepare(self.recipe_path, {'fex': self.source}, 'sample', self.root / 'output', **kwargs)

    def test_preparation_is_not_build_admission(self):
        with patch('subprocess.Popen', side_effect=AssertionError('process forbidden')), patch('os.system', side_effect=AssertionError('shell forbidden')):
            result = self.invoke()
        self.assertTrue(result['prepared'])
        self.assertEqual((self.root/'output/fixture.cpp').read_bytes(), self.fixture.read_bytes())
        for field in ('compiled','native_executed','native_execution_admitted','build_input_closure_complete'):
            self.assertIs(result[field], False)
        self.assertEqual(result['commands_executed'], [])
        self.assertEqual(result['tool_bindings']['status'], 'not_supplied')

    def test_changed_same_size_source_rejected_before_output(self):
        self.fixture.write_bytes(b'changed! fixture\n')
        with self.assertRaisesRegex(ValueError,'input_identity'): self.invoke()
        self.assertFalse((self.root/'output').exists())

    def test_missing_source_has_no_fallback(self):
        self.fixture.unlink()
        with self.assertRaises(FileNotFoundError): self.invoke()
        self.assertFalse((self.root/'output').exists())

    def test_unknown_control_rejected_before_output(self):
        with self.assertRaisesRegex(ValueError,'unknown_control'):
            tool.prepare(self.recipe_path,{'fex':self.source},'historical-unlisted',self.root/'output')
        self.assertFalse((self.root/'output').exists())

    def test_duplicate_json_key_is_not_silently_overwritten(self):
        self.recipe_path.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(ValueError,'duplicate_json_key'): self.invoke()

    def test_source_alias_and_relative_root_are_refused(self):
        alias=self.root/'alias'; alias.symlink_to(self.source,target_is_directory=True)
        for root in (alias,Path('relative')):
            with self.subTest(root=str(root)),self.assertRaisesRegex(ValueError,'path_alias_or_relative'):
                tool.prepare(self.recipe_path,{'fex':root},'sample',self.root/'output')

    def test_aliased_input_is_refused_even_with_identical_bytes(self):
        raw=self.fixture.read_bytes();self.fixture.unlink();other=self.source/'other.cpp';other.write_bytes(raw)
        self.fixture.symlink_to(other.name)
        with self.assertRaisesRegex(ValueError,'path_alias_or_relative'):self.invoke()

    def test_mode_mismatch_is_refused(self):
        self.fixture.chmod(0o755)
        with self.assertRaisesRegex(ValueError,'input_mode'):self.invoke()

    def test_existing_output_and_aliased_output_parent_refused(self):
        out=self.root/'output';out.mkdir()
        with self.assertRaisesRegex(ValueError,'fresh_output'):self.invoke()
        alias=self.root/'alias';alias.symlink_to(self.root,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'path_alias_or_relative'):
            tool.prepare(self.recipe_path,{'fex':self.source},'sample',alias/'new')

    def test_output_cannot_modify_source_tree(self):
        with self.assertRaisesRegex(ValueError,'output_source_overlap'):
            tool.prepare(self.recipe_path,{'fex':self.source},'sample',self.source/'generated')

    def test_recipe_traversal_and_duplicate_source_path_rejected(self):
        self.recipe['inputs']['fixture']['path']='../fixture.cpp';self.write_recipe()
        with self.assertRaisesRegex(ValueError,'relative_path'):self.invoke()
        self.recipe['inputs']['fixture']['path']='fixture.cpp'
        self.recipe['inputs']['alias']=dict(self.recipe['inputs']['fixture']);self.write_recipe()
        with self.assertRaisesRegex(ValueError,'duplicate_input_path'):self.invoke()

    def test_generated_identity_rejects_an_incorrect_extractor(self):
        self.recipe['cases']['sample']['generated']['fixture.cpp']['sha256']='0'*64;self.write_recipe()
        with self.assertRaisesRegex(ValueError,'generated_identity'):self.invoke()
        self.assertFalse((self.root/'output').exists())

    def test_source_change_after_output_creation_retains_failed_receipt(self):
        original=Path.mkdir
        def mkdir(path,*args,**kwargs):
            result=original(path,*args,**kwargs)
            if path==self.root/'output':self.fixture.write_bytes(b'changed during preparation\n')
            return result
        with patch.object(Path,'mkdir',mkdir),self.assertRaisesRegex(ValueError,'source_changed_during_prepare'):
            self.invoke()
        receipt=json.loads((self.root/'output/prepare.json').read_text())
        self.assertFalse(receipt['prepared']);self.assertFalse(receipt['native_executed'])
        self.assertEqual(receipt['error']['detail'],'source_changed_during_prepare')

    def tool_bindings(self):
        compiler=self.root/'clang';compiler.write_bytes(b'non-executable fake tool identity')
        alias=self.root/'clang++';alias.symlink_to(compiler.name)
        sdk=self.root/'sdk';sdk.mkdir();inventory=self.root/'sdk-inventory.json';inventory.write_text('{"files":[]}')
        value={'compiler':dict(path=str(alias),resolved_path=str(compiler),sha256=tool.digest(compiler.read_bytes()),size_bytes=compiler.stat().st_size),
            'sdk_root':str(sdk),'sdk_inventory_ref':tool.ref(inventory,inventory.read_bytes())}
        p=self.root/'bindings.json';p.write_text(json.dumps(value));return p,value

    def test_explicit_tool_alias_preserved_without_discovery_or_admission(self):
        p,value=self.tool_bindings()
        with patch('subprocess.Popen',side_effect=AssertionError('tool execution forbidden')):
            result=self.invoke(tool_bindings=p)
        self.assertEqual(result['tool_bindings']['compiler'],value['compiler'])
        self.assertFalse(result['tool_bindings']['sdk_entries_or_implicit_libraries_admitted'])
        self.assertFalse(result['native_execution_admitted'])

    def test_changed_tool_or_sdk_inventory_is_refused(self):
        p,value=self.tool_bindings();compiler=Path(value['compiler']['resolved_path']);original=compiler.read_bytes()
        compiler.write_bytes(b'changed tool')
        with self.assertRaisesRegex(ValueError,'compiler_identity'):self.invoke(tool_bindings=p)
        compiler.write_bytes(original);Path(value['sdk_inventory_ref']['path']).write_bytes(b'changed sdk inventory')
        with self.assertRaisesRegex(ValueError,'sdk_inventory_identity'):self.invoke(tool_bindings=p)
        self.assertFalse((self.root/'output').exists())

    def test_incomplete_tool_bindings_are_not_inferred(self):
        p=self.root/'bindings.json';p.write_text('{}')
        with self.assertRaisesRegex(ValueError,'tool_bindings_shape'):self.invoke(tool_bindings=p)

    def test_receipt_failure_never_masks_primary_source_failure(self):
        mkdir_original=Path.mkdir;write_original=Path.write_text
        def mkdir(path,*args,**kwargs):
            result=mkdir_original(path,*args,**kwargs)
            if path==self.root/'output':self.fixture.write_bytes(b'changed during preparation\n')
            return result
        def write(path,*args,**kwargs):
            if path.name=='prepare.json':raise OSError('evidence storage unavailable')
            return write_original(path,*args,**kwargs)
        with patch.object(Path,'mkdir',mkdir),patch.object(Path,'write_text',write):
            with self.assertRaisesRegex(ValueError,'source_changed_during_prepare') as caught:self.invoke()
        self.assertTrue(any('prepare_receipt_write_failed: evidence storage unavailable' in note
                            for note in caught.exception.__notes__))

    def test_receipt_failure_after_materialization_is_not_returned_as_pass(self):
        original=Path.write_text
        def write(path,*args,**kwargs):
            if path.name=='prepare.json':raise OSError('receipt failed')
            return original(path,*args,**kwargs)
        with patch.object(Path,'write_text',write),self.assertRaisesRegex(OSError,'receipt failed'):self.invoke()

    def test_boolean_tool_sizes_are_not_integer_identities(self):
        p,value=self.tool_bindings()
        compiler=Path(value['compiler']['resolved_path']);compiler.write_bytes(b'x')
        value['compiler'].update(size_bytes=True,sha256=tool.digest(b'x'));p.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError,'compiler_ref_shape'):self.invoke(tool_bindings=p)
        value['compiler']['size_bytes']=1
        inventory=Path(value['sdk_inventory_ref']['path']);inventory.write_bytes(b'0')
        value['sdk_inventory_ref'].update(size_bytes=True,sha256=tool.digest(b'0'));p.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError,'sdk_inventory_ref'):self.invoke(tool_bindings=p)

    def test_reader_bounds_a_stream_even_if_the_stat_was_small(self):
        class ObservedStream(io.BytesIO):
            def read(self,size=-1):
                self.requested=size
                return super().read(size)
        stream=ObservedStream(b'x'*(tool.MAX_FILE+10))
        with patch.object(Path,'open',return_value=stream),self.assertRaisesRegex(ValueError,'file_bound'):
            tool.read_file(self.fixture)
        self.assertEqual(stream.requested,tool.MAX_FILE+1)


class SelectedSourcePreparation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.recipe=tool.read_json(RECIPE)
        cls.roots={'fex':FEX}
        supplied=os.environ.get('PEAR_TEST_WINE_ROOT')
        if supplied:cls.roots['wine']=Path(supplied)

    def prepare(self,case,output):
        return tool.prepare(RECIPE,self.roots,case,output)

    def test_all13_sources_prepare_with_explicit_bindings_without_processes(self):
        self.assertIn('wine',self.roots,'Set PEAR_TEST_WINE_ROOT to the explicit canonical Wine source provider.')
        self.assertEqual(len(self.recipe['cases']),13)
        with tempfile.TemporaryDirectory() as temp,patch('subprocess.Popen',side_effect=AssertionError('native process forbidden')):
            root=Path(temp).resolve()
            for case in self.recipe['cases']:
                with self.subTest(case=case):
                    result=self.prepare(case,root/case)
                    self.assertTrue(result['prepared'])
                    self.assertFalse(result['native_execution_admitted'])
                    self.assertEqual(result['commands_executed'],[])
                    self.assertTrue(result['native_input_gaps'])

    def test_pmr_baseline_is_separate_from_selected_candidate(self):
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp).resolve()/'pmr';result=self.prepare('pmr-lifetime',output)
            baseline=(output/'baseline/resource_under_test.inc').read_bytes()
            current=(output/'candidate/resource_under_test.inc').read_bytes()
            self.assertNotEqual(baseline,current)
            self.assertEqual(hashlib.sha256(current.removeprefix(tool.DERIVED_MIT)).hexdigest(),
                             '01630cb63cbd9c44ad8f0f01bda5be4c05cb9d90dc20f2f013d9ee72416ae5ed')
            self.assertEqual(result['oracle']['baseline']['scope_retained_buffers'],1)
            self.assertEqual(result['oracle']['candidate']['scope_retained_buffers'],0)

    def test_current_census_copy_cannot_be_removed_from_generated_source(self):
        original=tool.attach
        def altered(text):return original(text).replace('    if (Diag) PearBindings::Copy(Diag->Census,Bindings,NextLifetimeSerial);\n','')
        with tempfile.TemporaryDirectory() as temp,patch.object(tool,'attach',altered):
            with self.assertRaisesRegex(ValueError,'generated_identity'):
                self.prepare('attach-branch',Path(temp).resolve()/'attach')

    def test_current_finite_vector_stays_in_exact_selected_body(self):
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp).resolve()/'finite';self.prepare('finite-construction',output)
            body=(output/'finite-selected-body.inc').read_bytes().removeprefix(tool.DERIVED_MIT)
            self.assertIn(b'fextl::vector<Reference> Extra;',body)
            self.assertIn(b'#include <FEXCore/fextl/vector.h>',(output/'finite_construction_under_test.inc').read_bytes())
            self.assertNotIn(b'using vector', (output/'finite_construction_under_test.inc').read_bytes())

    def test_checked_owner_branch_is_preserved_and_has_explicit_variant(self):
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp).resolve()/'checked';result=self.prepare('checked-data-memory',output)
            self.assertIn(b'#if !defined(_M_ARM64EC) || defined(PEAR_FEX_MEMORY_OWNER)',
                          (output/'checked_data_memory_under_test.inc').read_bytes())
            command=next(x for x in result['command_templates'] if x['id']=='ec_owner-compile')
            self.assertIn('-D_M_ARM64EC=1',command['argv_template'])
            self.assertIn('-DPEAR_FEX_MEMORY_OWNER=1',command['argv_template'])

    def test_missing_baseline_does_not_trigger_patch_or_old_root_fallback(self):
        recipe=copy.deepcopy(self.recipe)
        recipe['inputs']['pmr_baseline']['path']='Pear/Tests/Memory/Baselines/unavailable.inc'
        with tempfile.TemporaryDirectory() as temp,patch('subprocess.Popen',side_effect=AssertionError('patch forbidden')):
            root=Path(temp).resolve();path=root/'recipe.json';path.write_text(json.dumps(recipe))
            with self.assertRaises(FileNotFoundError):tool.prepare(path,self.roots,'pmr-lifetime',root/'pmr')
            self.assertFalse((root/'pmr').exists())

    def test_emitter_preserves_expected_refusal_without_claiming_fmt_present(self):
        with tempfile.TemporaryDirectory() as temp:
            result=self.prepare('emitter-labels',Path(temp).resolve()/'emitter')
            self.assertEqual(next(x['expected_exit'] for x in result['command_templates'] if x['id']=='private-into-direct'),97)
            self.assertTrue(any('fmt' in x for x in result['native_input_gaps']))
            self.assertFalse(result['compiled'])

    def test_runner_imports_are_inert_and_select_only_their_own_control(self):
        with patch('subprocess.Popen',side_effect=AssertionError('launch forbidden')),patch('os.system',side_effect=AssertionError('shell forbidden')):
            pmr=importlib.import_module('Pear.Tools.TestFixtures.run_pmr_lifetime')
            emitter=importlib.import_module('Pear.Tools.TestFixtures.emitter_check')
            importlib.reload(pmr);importlib.reload(emitter)
        for module,case in [(pmr,'pmr-lifetime'),(emitter,'emitter-labels')]:
            with patch.object(module,'prepare_main') as entry:
                module.main(['explicit arguments'])
                entry.assert_called_once_with(['explicit arguments'],fixed_case=case)


if __name__=='__main__':unittest.main()
