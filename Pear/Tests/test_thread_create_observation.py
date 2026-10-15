# SPDX-License-Identifier: MIT
import unittest
from Pear.Diagnostics import thread_create_observation as observation

def record(**changes):
    row=dict(pid=42,tid=24,call=1,stage=5,context=0x1000,thread=0x2000,slot=0x3000,
      life=0,life_known=0,status=4,domain=0,code=0,returned_status=4,returned_domain=0,returned_code=0,
      cleanup_attempted=1,cleanup_status=6,cleanup_domain=2,cleanup_code=-7,ready_before=1,ready_after=1)
    row.update(changes)
    return ('PEAR_CREATE1 '+' '.join(f'{k}={row[k]:x}' if k in observation.HEX else f'{k}={row[k]}' for k in observation.FIELDS)+'\n').encode()

class ConstructionObservationTests(unittest.TestCase):
    def test_preserves_primary_and_cleanup_separately(self):
        a=observation.assess(record(),{42});r=a['records'][0]
        self.assertEqual((r['stage_name'],r['status'],r['cleanup_status'],r['cleanup_code']),('attach',4,6,-7))
        for k in ('source_lifetime_known','first_global_cause_proven','complete_timeline','menu_verified','steamworks_verified'):
            self.assertFalse(a[k])
    def test_absence_is_not_success(self):
        a=observation.assess(b'ordinary log\n',{42});self.assertEqual(a['count'],0);self.assertFalse(a['first_global_cause_proven'])
    def test_every_stage_and_unconstructed_identity(self):
        for stage in range(1,8):
            self.assertEqual(observation.records(record(stage=stage,thread=0,cleanup_attempted=0),{42})[0]['stage'],stage)
    def test_foreign_process_and_replayed_first_record(self):
        for raw,owned in [(record(),{43}),(record()+record(),{42})]:
            with self.assertRaises(Exception):observation.records(raw,owned)
    def test_missing_truncated_and_unknown_fields(self):
        for raw in (record()[:-1],record()[:-14],record().replace(b'stage=5',b'phase=5'),record().replace(b'PEAR_CREATE1',b'PEAR_CREATE2'),record()+b'PEAR_CREATE1 pid=42'):
            with self.assertRaises(Exception):observation.records(raw,{42})
    def test_rejects_invented_lifetime_and_invalid_ranges(self):
        for changes in [dict(life=1),dict(life_known=1),dict(stage=8),dict(call=2),dict(tid=0),dict(status=0),dict(code=2**31),dict(domain=2**32),dict(ready_after=2),dict(slot=0)]:
            with self.subTest(changes=changes),self.assertRaises(Exception):observation.records(record(**changes),{42})
    def test_native_pid_separates_first_records(self):
        self.assertEqual(len(observation.records(record()+record(pid=43),{42,43})),2)
    def test_signed_error_and_full_pointer(self):
        r=observation.records(record(context=2**64-1,code=-2**31),{42})[0]
        self.assertEqual(r['context'],2**64-1);self.assertEqual(r['code'],-2**31)

if __name__=='__main__':unittest.main()
