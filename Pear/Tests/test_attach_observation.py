# SPDX-License-Identifier: MIT
import unittest
from Pear.Diagnostics import attach_observation as observe
from Pear.Tests.test_thread_create_observation import record as primary

def companion(**changes):
    row=dict(pid=42,tid=24,call=1,context=0x1000,thread=0x2000,slot=0x3000,
      branch=12,first=12,flags=1|64|256,context_serial=9,binding_serial=0,
      status=4,domain=0,code=0,intermediate_status=0,intermediate_domain=0,intermediate_code=0)
    row.update(changes)
    return ('PEAR_ATTACH1 '+' '.join(f'{k}={row[k]:x}' if k in observe.HEX else f'{k}={row[k]}' for k in observe.FIELDS)+'\n').encode()

class AttachObservationTests(unittest.TestCase):
    def test_capacity_bits_are_independent_and_not_a_fix(self):
        for capacity in (64,128,192):
            r=observe.assess(primary()+companion(flags=1|256|capacity),{42})
            self.assertEqual(r['records'][0]['flags']&192,capacity)
            self.assertEqual(r['missing_companions'],0)
            for key in ('source_lifetime_known','first_global_cause_proven','native_capacity_cause_proven','gameplay_verified','steamworks_verified'):
                self.assertFalse(r[key])
    def test_missing_companion_is_explicit_unknown(self):
        r=observe.assess(primary(),{42});self.assertEqual(r['missing_companions'],1)
        self.assertFalse(r['exact_return_site_observed'])
        self.assertEqual(observe.assess(b'ordinary log\n',{42})['count'],0)
    def test_original_reader_still_accepts_companion(self):
        self.assertEqual(len(observe.create.records(primary()+companion(),{42})),1)
    def test_finish_failure_keeps_native_intermediate(self):
        raw=primary(status=6,returned_status=6)+companion(branch=17,first=17,flags=4|8|512,
            context_serial=0,status=6,intermediate_status=0)
        r=observe.records(raw,{42})[0];self.assertEqual(r['intermediate_status'],0);self.assertEqual(r['status'],6)
    def test_native_failure_is_not_located_capacity_cause(self):
        raw=primary()+companion(branch=15,first=15,flags=4|8|16|512,context_serial=0,intermediate_status=4)
        self.assertFalse(observe.assess(raw,{42})['native_capacity_cause_proven'])
    def test_identity_stage_result_and_owner_must_join(self):
        for changes in ({'tid':25},{'context':0x1001},{'thread':0x2001},{'slot':0x3001},{'pid':43},{'status':3},{'domain':1},{'code':-1}):
            with self.subTest(changes=changes),self.assertRaises(Exception):observe.records(primary()+companion(**changes),{42,43})
        for head in (b'',primary(stage=6),primary(returned_status=3)):
            with self.subTest(head=head),self.assertRaises(Exception):observe.records(head+companion(),{42})
        with self.assertRaises(Exception):observe.records(primary()+companion(),{43})
    def test_duplicate_truncated_unknown_version_fields_refuse(self):
        for raw in (companion()+companion(),companion()[:-1],companion().replace(b'PEAR_ATTACH1',b'PEAR_ATTACH2'),
                    companion().replace(b'branch=12',b'return=12'),companion()+b'PEAR_ATTACH1 pid=42'):
            with self.subTest(raw=raw),self.assertRaises(Exception):observe.records(primary()+raw,{42})
    def test_invalid_flags_tags_ranges_and_unknown_fields_refuse(self):
        for changes in ({'branch':0},{'branch':18},{'first':0},{'flags':1024},{'flags':1},
                        {'flags':64},{'flags':4|512},{'flags':8|512},{'flags':1|256},
                        {'context_serial':0},{'binding_serial':1},{'flags':1|2|64|256},
                        {'intermediate_status':1},{'intermediate_domain':1},{'intermediate_code':1},
                        {'call':2},{'code':2**31},{'domain':2**32},{'context_serial':2**64},
                        {'intermediate_status':9},{'intermediate_domain':2**32},{'first':15},
                        {'branch':15,'first':15,'flags':0,'context_serial':0}):
            with self.subTest(changes=changes),self.assertRaises(Exception):observe.records(primary()+companion(**changes),{42})
    def test_native_precheck_can_fail_without_call_but_facts_cannot(self):
        raw=primary()+companion(branch=15,first=15,flags=4|512,context_serial=0,intermediate_status=4)
        self.assertEqual(observe.records(raw,{42})[0]['flags'],4|512)
        for flags in (4|16|512,4|32|512,4|8|16|32|512):
            with self.subTest(flags=flags),self.assertRaises(Exception):
                observe.records(primary()+companion(branch=15,first=15,flags=flags,context_serial=0,intermediate_status=4),{42})

    def test_every_return_site_except_capacity_can_be_unknown_serials(self):
        for tag in range(1,18):
            if tag==12:continue
            flags=(4|512) if tag in (15,16,17) else 512 if tag==6 else 0
            raw=primary()+companion(branch=tag,first=tag,flags=flags,context_serial=0,intermediate_status=4 if tag==15 else 0)
            self.assertEqual(observe.records(raw,{42})[0]['branch'],tag)

if __name__=='__main__':unittest.main()
