#pragma once
#include "PearTargetObservation.h"
#include "PearWriterRing.h"
extern "C" uint64_t PearWriterBegin(PearWriterRecord*,const void*,uint64_t);
extern "C" void PearWriterFinish(uint64_t,bool,uint64_t,uint64_t,uint64_t,bool,bool);
extern "C" bool PearWriterSnapshot(const void*,uint64_t,PearWriterBatch*);
extern "C" void PearWriterEmit(const PearTargetRecord*,const PearWriterBatch*);
struct PearWriterScope {
  uint64_t ticket{},status{},domain{},code{};
  bool stored{},published{},updated{};
  PearWriterScope(bool enabled,PearWriterRecord* r,const void* thread,uint64_t life) {
    if(enabled)ticket=PearWriterBegin(r,thread,life);
  }
  ~PearWriterScope(){if(ticket)PearWriterFinish(ticket,stored,status,domain,code,published,updated);}
  PearWriterScope(const PearWriterScope&)=delete;
  PearWriterScope& operator=(const PearWriterScope&)=delete;
};
