#pragma once
#include "PearAbortObservation.h"
#include <stddef.h>
struct PearReadIdentity {
  uint64_t seen {};
  uint64_t owner {};
  uint64_t state {};
  uint64_t base {};
  uint64_t owner_pid {};
  uint64_t allocation {};
  uint64_t generation {};
  uint64_t extent {};
  uint64_t size {};
  uint64_t epoch {};
  uint64_t expected {};
  uint64_t aclass {};
  uint64_t role {};
  uint64_t offset {};
  uint64_t bytes {};
  uint64_t writer_seen {},writer_cut {},writer_loss {};
};
extern "C" uint64_t PearReadIdentityBegin(const void*,const void*,size_t,size_t);
extern "C" void PearReadIdentityEnd(uint64_t,PearReadIdentity*);
// Stack-bound diagnostic lifetime only; never grants a memory lease.
struct PearReadIdentityScope {
  PearReadIdentity* record {};
  uint64_t ticket {};
  PearReadIdentityScope(bool enabled,PearReadIdentity* r,const void* thread,const void* dest,size_t offset,size_t bytes) {
    if (enabled && r) { *r={};ticket=PearReadIdentityBegin(thread,dest,offset,bytes);if(ticket)record=r; }
  }
  ~PearReadIdentityScope(){if(record) PearReadIdentityEnd(ticket,record);}
  PearReadIdentityScope(const PearReadIdentityScope&)=delete;
  PearReadIdentityScope& operator=(const PearReadIdentityScope&)=delete;
};
struct PearTargetRecord {
  PearAbortRecord abort;
  PearReadIdentity read;
  uint64_t write_owner {};
  uint64_t write_state {};
  uint64_t write_base {};
  uint64_t write_offset {};
  uint64_t write_bytes {};
};
static inline int pear_target_format(char* out,size_t cap,const PearTargetRecord* d) { return snprintf(out,cap,"PEAR_TARGET1 pid=%llu tid=%llu guard=%llu call=%llu life=%llu allocation=%llu generation=%llu extent=%llu size=%llu epoch=%llu expected=%llu aclass=%llu role=%llu continuation=%llu read_seen=%llu read_owner=%llu read_state=%llu read_base=%llu read_owner_pid=%llu read_allocation=%llu read_generation=%llu read_extent=%llu read_size=%llu read_epoch=%llu read_expected=%llu read_aclass=%llu read_role=%llu read_offset=%llu read_bytes=%llu write_owner=%llu write_state=%llu write_base=%llu write_offset=%llu write_bytes=%llu\n",(unsigned long long)d->abort.pid,(unsigned long long)d->abort.tid,(unsigned long long)d->abort.guard,(unsigned long long)d->abort.call,(unsigned long long)d->abort.life,(unsigned long long)d->abort.allocation,(unsigned long long)d->abort.generation,(unsigned long long)d->abort.extent,(unsigned long long)d->abort.size,(unsigned long long)d->abort.epoch,(unsigned long long)d->abort.expected,(unsigned long long)d->abort.aclass,(unsigned long long)d->abort.role,(unsigned long long)d->abort.continuation,(unsigned long long)d->read.seen,(unsigned long long)d->read.owner,(unsigned long long)d->read.state,(unsigned long long)d->read.base,(unsigned long long)d->read.owner_pid,(unsigned long long)d->read.allocation,(unsigned long long)d->read.generation,(unsigned long long)d->read.extent,(unsigned long long)d->read.size,(unsigned long long)d->read.epoch,(unsigned long long)d->read.expected,(unsigned long long)d->read.aclass,(unsigned long long)d->read.role,(unsigned long long)d->read.offset,(unsigned long long)d->read.bytes,(unsigned long long)d->write_owner,(unsigned long long)d->write_state,(unsigned long long)d->write_base,(unsigned long long)d->write_offset,(unsigned long long)d->write_bytes); }
extern "C" void PearTargetEmit(const PearTargetRecord*);
