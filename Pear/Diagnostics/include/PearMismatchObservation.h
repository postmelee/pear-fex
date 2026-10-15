#pragma once
#include "PearAbortObservation.h"
#include <stddef.h>
// Private later snapshot; no request ABI or target class layout changes.
struct PearMismatchRecord {
  PearAbortRecord abort;
  uint64_t pc;
  uint64_t offset;
  uint64_t window_owner;
  uint64_t window_base;
  uint64_t window_size;
  uint64_t data;
  uint64_t captured_epoch;
  uint64_t kind;
  uint64_t count;
  uint64_t store0;
  uint64_t store1;
  int64_t delta;
  uint32_t original[13];
  uint32_t actual[13];
  uint32_t next[13];
};
static inline int pear_mismatch_format(char *out, size_t cap, const PearMismatchRecord *d) {
  int n=snprintf(out,cap,"PEAR_MISMATCH1 pid=%llu tid=%llu guard=%llu call=%llu life=%llu allocation=%llu generation=%llu extent=%llu size=%llu epoch=%llu expected=%llu aclass=%llu role=%llu continuation=%llu pc=%llu offset=%llu window_owner=%llu window_base=%llu window_size=%llu data=%llu captured_epoch=%llu kind=%llu count=%llu store0=%llu store1=%llu delta=%lld",(unsigned long long)d->abort.pid,(unsigned long long)d->abort.tid,(unsigned long long)d->abort.guard,(unsigned long long)d->abort.call,(unsigned long long)d->abort.life,(unsigned long long)d->abort.allocation,(unsigned long long)d->abort.generation,(unsigned long long)d->abort.extent,(unsigned long long)d->abort.size,(unsigned long long)d->abort.epoch,(unsigned long long)d->abort.expected,(unsigned long long)d->abort.aclass,(unsigned long long)d->abort.role,(unsigned long long)d->abort.continuation,(unsigned long long)d->pc,(unsigned long long)d->offset,(unsigned long long)d->window_owner,(unsigned long long)d->window_base,(unsigned long long)d->window_size,(unsigned long long)d->data,(unsigned long long)d->captured_epoch,(unsigned long long)d->kind,(unsigned long long)d->count,(unsigned long long)d->store0,(unsigned long long)d->store1,(long long)d->delta);
  if(n<0 || static_cast<size_t>(n)>=cap) return -1;
  size_t used=static_cast<size_t>(n);
  n=snprintf(out+used,cap-used," original=");
  if(n<0 || static_cast<size_t>(n)>=cap-used) return -1;
  used+=n;
  for(unsigned i=0;i<13;++i) {
    n=snprintf(out+used,cap-used,"%08x",static_cast<unsigned>(d->original[i]));
    if(n!=8 || static_cast<size_t>(n)>=cap-used) return -1;
    used+=n;
  }
  n=snprintf(out+used,cap-used," actual=");
  if(n<0 || static_cast<size_t>(n)>=cap-used) return -1;
  used+=n;
  for(unsigned i=0;i<13;++i) {
    n=snprintf(out+used,cap-used,"%08x",static_cast<unsigned>(d->actual[i]));
    if(n!=8 || static_cast<size_t>(n)>=cap-used) return -1;
    used+=n;
  }
  n=snprintf(out+used,cap-used," next=");
  if(n<0 || static_cast<size_t>(n)>=cap-used) return -1;
  used+=n;
  for(unsigned i=0;i<13;++i) {
    n=snprintf(out+used,cap-used,"%08x",static_cast<unsigned>(d->next[i]));
    if(n!=8 || static_cast<size_t>(n)>=cap-used) return -1;
    used+=n;
  }
  if(cap-used<2) return -1;
  out[used++]='\n'; out[used]='\0'; return static_cast<int>(used);
}
extern "C" void PearMismatchEmit(const PearMismatchRecord*);
