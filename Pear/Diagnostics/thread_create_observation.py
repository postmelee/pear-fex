# SPDX-License-Identifier: MIT
"""Strict D26 first construction-failure reader; identity is not source lifetime."""
import re
from Pear.Diagnostics.validation import need
STAGES={1:'context-hold',2:'admission',3:'construction-slot',4:'storage-allocation',5:'attach',6:'initial-buffer',7:'compiler'}
FIELDS='pid tid call stage context thread slot life life_known status domain code returned_status returned_domain returned_code cleanup_attempted cleanup_status cleanup_domain cleanup_code ready_before ready_after'.split()
HEX={'context','thread','slot'}
SIGNED={'code','returned_code','cleanup_code'}
BOOL={'life_known','cleanup_attempted','ready_before','ready_after'}

def records(raw,owned):
    need(type(raw) is bytes and len(raw)<=64*1024**2,'create_stream_bound')
    result=[];seen=set()
    for line in raw.splitlines(keepends=True):
        if b'PEAR_CREATE' not in line:continue
        need(line.startswith(b'PEAR_CREATE1 ') and line.endswith(b'\n') and len(line)<640,'create_shape')
        line=line[:-1]
        parts=line[len(b'PEAR_CREATE1 '):].split(b' ');need(len(parts)==len(FIELDS),'create_fields')
        row={}
        for key,part in zip(FIELDS,parts):
            prefix=(key+'=').encode();need(part.startswith(prefix),'create_order');s=part[len(prefix):]
            need(re.fullmatch(rb'[0-9a-f]+' if key in HEX else rb'-?[0-9]+' if key in SIGNED else rb'[0-9]+',s),'create_number')
            row[key]=int(s,16 if key in HEX else 10)
            need((-2**31<=row[key]<2**31) if key in SIGNED else (0<=row[key]<2**64),'create_range')
        need(row['pid'] in owned and 0<row['pid']<2**32 and 0<row['tid']<2**32,'create_identity')
        need(row['pid'] not in seen and row['call']==1,'create_duplicate');seen.add(row['pid'])
        need(row['stage'] in STAGES and row['context'] and row['slot'],'create_stage')
        need(row['life']==0 and row['life_known']==0,'create_unknown_lifetime')
        need(all(row[k] in (0,1) for k in BOOL),'create_boolean')
        need(1<=row['status']<=8 and 0<=row['returned_status']<=8 and 0<=row['cleanup_status']<=8,'create_status')
        need(all(row[k]<2**32 for k in ('domain','returned_domain','cleanup_domain')),'create_domain')
        row['stage_name']=STAGES[row['stage']];result.append(row)
    return result

def assess(raw,owned):
    rows=records(raw,owned)
    return dict(records=rows,count=len(rows),source_lifetime_known=False,first_global_cause_proven=False,
                complete_timeline=False,menu_verified=False,steamworks_verified=False)
