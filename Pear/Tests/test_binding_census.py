# SPDX-License-Identifier: MIT
import unittest
from Pear.Diagnostics import binding_census_observation as observe
from Pear.Tests.test_attach_observation import primary,companion
KEY=dict(pid=42,tid=24,call=1,context=0x1000,thread=0x2000,slot=0x3000)
def line(tag,values):
    return (tag+' '+' '.join(f'{k}={values[k]:x}' if k in observe.HEX else f'{k}={values[k]}' for k in observe.FIELDS[tag])+'\n').encode()
def census(occupied=64,serial=100):
    data=[line('PEAR_BINDINGS1',dict(KEY,rows=64,occupied=occupied,next_serial=serial))]
    for i in range(64):
        r=dict.fromkeys(observe.ROW,0);r.update(KEY,index=i,teb=i+1 if i<occupied else 0,windows_tid=i+1,serial=i+1,kind=2)
        data.append(line('PEAR_BINDING1',r))
    data.append(line('PEAR_BINDINGS_END1',dict(KEY,rows=64)));return data
class CensusTests(unittest.TestCase):
    def assess(self,parts,flags=321):return observe.assess(primary()+companion(flags=flags)+b''.join(parts),{42})
    def test_complete_rows_are_not_liveness_or_reclamation(self):
        r=self.assess(census());self.assertEqual(r['complete_count'],1)
        self.assertEqual(len(r['snapshots'][0]['rows']),64)
        for k in ('native_thread_liveness_known','reclamation_safe','first_global_cause_proven','gameplay_verified'):self.assertFalse(r[k])
    def test_missing_and_partial_are_explicit(self):
        self.assertEqual(self.assess([])['missing_count'],1)
        for count in (1,2,64,65):
            r=self.assess(census()[:count]);self.assertEqual(r['incomplete_count'],1);self.assertFalse(r['source_rows_observed'])
    def test_serial_refusal_can_have_empty_slots(self):
        self.assertEqual(self.assess(census(0,2**64-1),385)['complete_count'],1)
        self.assertEqual(self.assess(census(64,2**64-1),449)['complete_count'],1)
    def test_rows_join_exact_invocation(self):
        for field in KEY:
            parts=census();parts[2]=parts[2].replace((field+'='+format(KEY[field],'x' if field in observe.HEX else 'd')).encode(),(field+'=9999').encode(),1)
            with self.subTest(field=field),self.assertRaises(Exception):self.assess(parts)
    def test_duplicate_reordered_and_early_end_refuse(self):
        c=census()
        for parts in ([c[0],*c],c+[c[-1]],c[:3]+[c[2]]+c[3:],[c[0],c[2],c[1],*c[3:]],[c[0],c[-1]]):
            with self.assertRaises(Exception):self.assess(parts)
    def test_malformed_truncation_versions_ranges(self):
        for a,b in ((b'PEAR_BINDING1',b'PEAR_BINDING2'),(b'flags=0',b'flags=128'),(b'kind=2',b'kind=3'),
                    (b'windows_tid=1 ',b'windows_tid=4294967296 '),(b'holds=0',b'holds=-1'),(b'active_kind=0',b'active_kind=4')):
            c=census();c[1]=c[1].replace(a,b)
            with self.subTest(a=a),self.assertRaises(Exception):self.assess(c)
        c=census();c[-1]=c[-1][:-1]
        with self.assertRaises(Exception):self.assess(c)
    def test_occupied_and_capacity_claims_must_match(self):
        for parts,flags in ((census(63),321),(census(),385),(census(64,2**64-1),321)):
            with self.assertRaises(Exception):self.assess(parts,flags)
        c=census();c[2]=c[2].replace(b'teb=2',b'teb=0')
        with self.assertRaises(Exception):self.assess(c)
    def test_old_readers_accept_companion(self):
        raw=primary()+companion()+b''.join(census())
        self.assertEqual(len(observe.attach.records(raw,{42})),1)
        self.assertEqual(len(observe.attach.create.records(raw,{42})),1)
if __name__=='__main__':unittest.main()
