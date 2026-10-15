// SPDX-License-Identifier: MIT
#pragma once
#include <cstdio>
#include "PearBindingCensus.h"
namespace PearBindings {
// Called only after the original source call returned and RegistryGuard unlocked.
// The existing first-failure recorder supplies the exact captured invocation.
template<class Record,class Sink>
void Emit(const Record& r,Sink output) {
  const auto& s=r.Attach.Census;
  if (s.Count!=Capacity) return;
  char key[224],text[640];
  const int n=snprintf(key,sizeof(key),"pid=%llu tid=%llu call=1 context=%llx thread=%llx slot=%llx",
    (unsigned long long)r.Process,(unsigned long long)r.ThreadID,
    (unsigned long long)r.Context,(unsigned long long)r.Thread,(unsigned long long)r.OutcomeSlot);
  if (n<0 || size_t(n)>=sizeof(key)) return;
  auto send=[&](int size) { if (size>=0 && size_t(size)<sizeof(text)) output(text); };
  send(snprintf(text,sizeof(text),"PEAR_BINDINGS1 %s rows=%u occupied=%u next_serial=%llu\n",
    key,s.Count,s.Occupied,(unsigned long long)s.NextSerial));
  for (uint32_t i=0;i<Capacity;++i) {
    const auto& b=s.Rows[i];
    send(snprintf(text,sizeof(text),"PEAR_BINDING1 %s index=%u teb=%llx windows_tid=%llu source=%llx source_context=%llx attempt=%llx executor=%llu serial=%llu flags=%u holds=%u role=%u kind=%u transition=%u active_kind=%u original_status=%u cleanup_status=%u\n",
      key,i,(unsigned long long)b.TEB,(unsigned long long)b.WindowsTid,
      (unsigned long long)b.Source,(unsigned long long)b.Context,(unsigned long long)b.Attempt,
      (unsigned long long)b.Executor,(unsigned long long)b.Serial,b.Flags,b.Holds,b.Role,b.Kind,
      b.Transition,b.ActiveKind,b.OriginalStatus,b.CleanupStatus));
  }
  send(snprintf(text,sizeof(text),"PEAR_BINDINGS_END1 %s rows=%u\n",key,s.Count));
}
}
