# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
import unittest
from Pear.Diagnostics import slot_lifetime_observation as s

def event(**changes):
    r=dict.fromkeys(s.FIELDS,0)
    r.update(pid=42,tid=24,call=1,stage=2,side=1,context=0x100,source=0x200,serial=9,
             snapshot=1,row_context=0x100,row_source=0x200,row_serial=9,executor=7)
    r.update(changes)
    return ('PEAR_SLOT1 '+' '.join(k+'='+format(r[k],'x' if k in s.HEX else 'd') for k in s.FIELDS)+'\n').encode()

class SlotTests(unittest.TestCase):
    def test_return_and_row_removal_are_not_liveness_or_reclamation(self):
        a=s.assess(event()+event(side=2,kind=2,returned=1,destroyed=1,freed=1,snapshot=0,row_context=0,row_source=0,row_serial=0,executor=0),{42})
        self.assertEqual(a['complete_count'],1)
        for k in ('coverage_complete','native_thread_liveness_known','reclamation_safe','gameplay_verified'):self.assertFalse(a[k])
    def test_original_refusal_domain_and_code_preserved(self):
        r=s.assess(event()+event(side=2,kind=2,status=3,domain=1,code=-5),{42})['calls'][0]['returned']
        self.assertEqual((r['status'],r['domain'],r['code']),(3,1,-5))
    def test_missing_return_is_unknown(self):self.assertEqual(s.assess(event(),{42})['incomplete_count'],1)
    def test_absent_observations_are_not_coverage(self):self.assertFalse(s.assess(b'normal log\n',{42})['coverage_complete'])
    def test_busy_snapshot_has_no_fabricated_serial(self):
        a=event(snapshot=2,serial=0,row_context=0,row_source=0,row_serial=0,executor=0)
        self.assertEqual(s.assess(a,{42})['incomplete_count'],1)
        with self.assertRaises(Exception):s.assess(event(snapshot=2),{42})
    def test_identity_mismatch_cannot_join(self):
        for k in s.KEY:
            if k=='call':continue
            with self.subTest(k=k),self.assertRaises(Exception):s.assess(event()+event(side=2,kind=2,**{k:99}),{42,99})
    def test_duplicate_out_of_order_truncation(self):
        a=event();b=event(side=2,kind=2)
        for raw in (a+a,b+a,a+b+b,a+b[:-1]):
            with self.assertRaises(Exception):s.assess(raw,{42})
    def test_slot_reuse_keeps_original_serial_distinct(self):
        d=s.assess(event()+event(side=2,kind=2,row_serial=10),{42})
        self.assertEqual(d['calls'][0]['entry']['serial'],9)
        self.assertEqual(d['calls'][0]['returned']['row_serial'],10)
    def test_nested_calls_may_interleave(self):
        d=s.assess(event()+event(call=2,stage=3)+event(call=2,stage=3,side=2,kind=2)+event(side=2,kind=2),{42})
        self.assertEqual(d['complete_count'],2)
    def test_loss_is_explicit_and_unique(self):
        loss=b'PEAR_SLOT_LOSS1 pid=42 limit=512 reason=1\n'
        self.assertEqual(len(s.assess(event()+loss,{42})['losses']),1)
        with self.assertRaises(Exception):s.assess(loss+loss,{42})
    def test_range_version_and_foreign_pid_refuse(self):
        for raw in (event(pid=43),event(call=513),event(flags=128),event(tid=0),event(stage=5),event().replace(b'PEAR_SLOT1',b'PEAR_SLOT2')):
            with self.assertRaises(Exception):s.assess(raw,{42})
    def test_ntstatus_is_distinct_from_pear_result(self):
        d=s.assess(event(stage=1)+event(stage=1,side=2,kind=1,status=0xc00000bb),{42})
        self.assertEqual(d['complete_count'],1)
        with self.assertRaises(Exception):s.assess(event()+event(side=2,kind=2,status=0xc00000bb),{42})

if __name__=='__main__':unittest.main()
