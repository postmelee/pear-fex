# SPDX-License-Identifier: MIT
"""D33 companion records join one captured stage5 failure; no lifetime inference."""
import re
from Pear.Diagnostics.validation import need
from Pear.Diagnostics import thread_create_observation as create
BRANCHES=dict(enumerate(('unknown','attach-invalid','attach-admission','attach-existing-prior',
    'attach-existing-state','attach-same-role','attach-same-idle','attach-bootstrap-unregister',
    'attach-bootstrap-transfer','bind-admission','bind-input-or-context','bind-existing-state',
    'bind-capacity','register-admission','register-precheck','register-invoke','register-shape',
    'register-finish-identity')))
FIELDS='pid tid call context thread slot branch first flags context_serial binding_serial status domain code intermediate_status intermediate_domain intermediate_code'.split()
HEX={'context','thread','slot'}
SIGNED={'code','intermediate_code'}
KEYS=('pid','tid','call','context','thread','slot')

def records(raw,owned):
    need(type(raw) is bytes and len(raw)<=64*1024**2,'attach_stream_bound')
    originals=create.records(raw,owned);by_key={tuple(r[k] for k in KEYS):r for r in originals}
    rows=[];seen=set()
    for line in raw.splitlines(keepends=True):
        if b'PEAR_ATTACH' not in line:continue
        need(line.startswith(b'PEAR_ATTACH1 ') and line.endswith(b'\n') and len(line)<640,'attach_shape')
        parts=line[len(b'PEAR_ATTACH1 '):-1].split(b' ');need(len(parts)==len(FIELDS),'attach_fields');row={}
        for k,part in zip(FIELDS,parts):
            prefix=(k+'=').encode();need(part.startswith(prefix),'attach_order');s=part[len(prefix):]
            need(re.fullmatch(rb'[0-9a-f]+' if k in HEX else rb'-?[0-9]+' if k in SIGNED else rb'[0-9]+',s),'attach_number')
            row[k]=int(s,16 if k in HEX else 10)
            need((-2**31<=row[k]<2**31) if k in SIGNED else (0<=row[k]<2**64),'attach_range')
        need(row['pid'] in owned and 0<row['pid']<2**32 and 0<row['tid']<2**32 and row['call']==1,'attach_identity')
        need(row['pid'] not in seen,'attach_duplicate');seen.add(row['pid'])
        need(row['branch'] in BRANCHES and row['branch']!=0 and row['first'] in BRANCHES and row['first']!=0,'attach_tag')
        flags=row['flags'];need(flags<1024,'attach_flags')
        for bit,key in ((1,'context_serial'),(2,'binding_serial')):
            need((row[key]>0) if flags&bit else row[key]==0,'attach_serial_known')
        need(not flags&56 or bool(flags&4),'attach_bridge_known')
        need(not flags&48 or bool(flags&8),'attach_bridge_called')
        need(flags&48!=48,'attach_bridge_exclusive')
        need(not flags&4 or bool(flags&512),'attach_bridge_result')
        need((bool(flags&192) and row['branch']==12) if flags&256 else not flags&192,'attach_capacity_known')
        need((row['branch']==12)==bool(flags&256),'attach_capacity_tag')
        need(row['first']==row['branch'] or (row['branch']==17 and row['first'] in (15,16)),'attach_first_local')
        if row['branch'] in (15,16,17):need(flags&4 and flags&512,'attach_register_facts')
        else:need(not flags&60,'attach_unrelated_bridge_facts')
        if row['branch']==6:need(flags&512,'attach_idle_facts')
        elif row['branch'] not in (15,16,17):need(not flags&512,'attach_unrelated_intermediate')
        need(1<=row['status']<=8 and row['domain']<2**32,'attach_status')
        need(0<=row['intermediate_status']<=8 and row['intermediate_domain']<2**32,'attach_intermediate_range')
        if not flags&512:
            need(all(row[k]==0 for k in ('intermediate_status','intermediate_domain','intermediate_code')),'attach_intermediate_unknown')
        if row['first']==15:
            need(all(row[k]==row['intermediate_'+k] for k in ('status','domain','code')),'attach_invoke_result')
        if row['first']==16:need(row['intermediate_status']==0,'attach_shape_primary_success')
        original=by_key.get(tuple(row[k] for k in KEYS))
        need(original is not None and original['stage']==5,'attach_failure_join')
        for key in ('status','domain','code'):
            need(row[key]==original[key]==original['returned_'+key],'attach_result_join')
        row['branch_name']=BRANCHES[row['branch']];row['first_local_failure_name']=BRANCHES[row['first']]
        rows.append(row)
    return rows

def assess(raw,owned):
    rows=records(raw,owned);failures=[r for r in create.records(raw,owned) if r['stage']==5]
    return dict(records=rows,count=len(rows),missing_companions=len(failures)-len(rows),
        exact_return_site_observed=bool(rows),source_lifetime_known=False,
        first_global_cause_proven=False,native_capacity_cause_proven=False,
        gameplay_verified=False,steamworks_verified=False)
