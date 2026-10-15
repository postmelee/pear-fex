# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Strict bounded lifecycle events; observations do not authorize reclamation."""
import re
from Pear.Diagnostics.validation import need
FIELDS='pid tid call stage side context source serial snapshot row_context row_source row_serial executor holds flags kind status domain code returned destroyed freed bridge_called validated'.split()
HEX={'context','source','row_context','row_source'}
KEY='pid tid call stage context source serial'.split()


def parse_number(key,raw):
    pattern=rb'-?(0|[1-9][0-9]*)' if key=='code' else rb'[0-9a-f]+' if key in HEX else rb'[0-9]+'
    need(re.fullmatch(pattern,raw),'slot_number')
    n=int(raw,16 if key in HEX else 10)
    need(-(2**31)<=n<2**31 if key=='code' else 0<=n<2**64,'slot_number_range')
    return n


def assess(raw,owned):
    need(type(raw) is bytes and len(raw)<=64*1024**2,'slot_stream_bound')
    groups={};losses=[];line_counts={}
    for line in raw.splitlines(keepends=True):
        if b'PEAR_SLOT' not in line:continue
        need(line.endswith(b'\n') and len(line)<768,'slot_line_shape')
        parts=line[:-1].split(b' ');tag=parts.pop(0)
        fields=FIELDS if tag==b'PEAR_SLOT1' else ['pid','limit','reason'] if tag==b'PEAR_SLOT_LOSS1' else None
        need(fields is not None and len(parts)==len(fields),'slot_fields')
        row={}
        for key,part in zip(fields,parts):
            need(part.startswith((key+'=').encode()),'slot_field_order')
            row[key]=parse_number(key,part[len(key)+1:])
        pid=row['pid'];need(pid in owned and pid>0,'slot_owned_pid')
        line_counts[pid]=line_counts.get(pid,0)+1;need(line_counts[pid]<=1025,'slot_output_bound')
        if tag==b'PEAR_SLOT_LOSS1':
            need(row['limit']==512 and row['reason'] in (1,2,3) and not any(x['pid']==pid for x in losses),'slot_loss_shape')
            losses.append(row);continue
        need(0<row['tid']<2**32 and 1<=row['call']<=512 and 1<=row['stage']<=4,'slot_identity')
        need(row['side'] in (1,2) and row['snapshot'] in (0,1,2),'slot_side_snapshot')
        need(row['flags']<128 and row['holds']<2**32 and row['status']<2**32 and row['domain']<=3,'slot_state_range')
        for key in ['returned','destroyed','freed','bridge_called','validated']:need(row[key] in (0,1),'slot_boolean')
        if row['snapshot']!=1:
            need(not any(row[k] for k in ('row_context','row_source','row_serial','executor','holds','flags')),'slot_unavailable_row')
        else:need(row['row_context'] and row['row_source'] and row['row_serial'],'slot_copied_identity')
        if row['side']==1:
            need(not any(row[k] for k in ('kind','status','domain','code','returned','destroyed','freed','bridge_called','validated')),'slot_entry_result')
            if row['snapshot']==1:need(all(row[k]==row['row_'+k] for k in ('context','source','serial')),'slot_entry_binding')
            else:need(row['serial']==0,'slot_unknown_serial')
        else:
            need(row['kind']==(1 if row['stage']==1 else 2),'slot_return_kind')
            if row['kind']==2:need(row['status']<=8,'slot_pear_status')
            if row['stage']!=2:need(not row['destroyed'] and not row['freed'],'slot_destroy_scope')
            if row['stage']!=4:need(not row['bridge_called'] and not row['validated'],'slot_bridge_scope')
        key=(pid,row['call']);g=groups.setdefault(key,dict(entry=None,returned=None))
        if row['side']==1:
            need(g['entry'] is None and g['returned'] is None,'slot_duplicate_entry');g['entry']=row
        else:
            need(g['entry'] is not None and g['returned'] is None,'slot_return_order')
            need(all(g['entry'][k]==row[k] for k in KEY),'slot_return_join');g['returned']=row
    pairs=list(groups.values())
    return dict(calls=pairs,complete_count=sum(x['returned'] is not None for x in pairs),
      incomplete_count=sum(x['returned'] is None for x in pairs),losses=losses,
      observations_present=bool(pairs),coverage_complete=False,native_thread_liveness_known=False,
      reclamation_safe=False,down_causality_proven=False,gameplay_verified=False)
