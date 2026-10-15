# SPDX-License-Identifier: MIT
"""Strict bounded companion census; missing records and native liveness stay unknown."""
import re
from Pear.Diagnostics.validation import need
from Pear.Diagnostics import attach_observation as attach
KEYS=attach.KEYS
ROW='index teb windows_tid source source_context attempt executor serial flags holds role kind transition active_kind original_status cleanup_status'.split()
FIELDS={'PEAR_BINDINGS1':[*KEYS,'rows','occupied','next_serial'],
        'PEAR_BINDING1':[*KEYS,*ROW],'PEAR_BINDINGS_END1':[*KEYS,'rows']}
HEX={'context','thread','slot','teb','source','source_context','attempt'}

def assess(raw,owned):
    need(type(raw) is bytes and len(raw)<=64*1024**2,'census_stream_bound')
    parents=attach.records(raw,owned);by_key={tuple(r[k] for k in KEYS):r for r in parents}
    groups={};total=0
    for line in raw.splitlines(keepends=True):
        if b'PEAR_BINDING' not in line:continue
        total+=len(line);need(total<=64*1024*max(1,len(owned)),'census_output_bound')
        need(line.endswith(b'\n') and len(line)<640,'census_line_shape')
        pieces=line[:-1].split(b' ')
        try:tag=pieces[0].decode('ascii')
        except UnicodeError:raise ValueError('census_tag')
        need(tag in FIELDS and len(pieces)==len(FIELDS[tag])+1,'census_fields')
        row={}
        for k,part in zip(FIELDS[tag],pieces[1:]):
            prefix=(k+'=').encode();need(part.startswith(prefix),'census_field_order');s=part[len(prefix):]
            need(re.fullmatch(rb'[0-9a-f]+' if k in HEX else rb'[0-9]+',s),'census_number')
            row[k]=int(s,16 if k in HEX else 10);need(0<=row[k]<2**64,'census_range')
        key=tuple(row[k] for k in KEYS);p=by_key.get(key)
        need(p is not None and p['branch']==12 and p['status']==4,'census_failure_join')
        g=groups.setdefault(key,dict(header=None,rows=[],end=None))
        if tag=='PEAR_BINDINGS1':
            need(g['header'] is None and not g['rows'] and g['end'] is None,'census_duplicate_header')
            need(row['rows']==64 and row['occupied']<=64,'census_capacity')
            need(bool(p['flags']&64)==(row['occupied']==64),'census_no_empty_join')
            need(bool(p['flags']&128)==(row['next_serial']==2**64-1),'census_serial_join')
            g['header']=row
        elif tag=='PEAR_BINDING1':
            need(g['header'] is not None and g['end'] is None,'census_row_order')
            need(row['index']==len(g['rows']) and row['index']<64,'census_row_index')
            need(row['flags']<128 and row['kind']<=2 and row['transition']<=7 and row['active_kind']<=3,'census_row_enum')
            for k in ('holds','role','windows_tid'):need(row[k]<2**32,'census_row_uint32')
            need(row['original_status']<=8 and row['cleanup_status']<=8,'census_row_status')
            g['rows'].append(row)
        else:
            need(g['header'] is not None and g['end'] is None and row['rows']==64 and len(g['rows'])==64,'census_end_shape')
            need(sum(bool(r['teb']) for r in g['rows'])==g['header']['occupied'],'census_occupied_rows')
            g['end']=row
    complete=[g for g in groups.values() if g['end'] is not None]
    expected=sum(p['branch']==12 for p in parents)
    return dict(snapshots=complete,complete_count=len(complete),incomplete_count=sum(g['end'] is None for g in groups.values()),
        missing_count=expected-len(groups),source_rows_observed=bool(complete),native_thread_liveness_known=False,
        reclamation_safe=False,first_global_cause_proven=False,gameplay_verified=False)
