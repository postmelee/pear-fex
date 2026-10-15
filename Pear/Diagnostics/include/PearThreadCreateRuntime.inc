// SPDX-License-Identifier: MIT
#ifdef PEAR_PHASE_OBSERVE
#include "PearThreadCreateObservation.h"
#include "PearBindingCensusEmit.h"
static PearThreadCreate::Recorder PearThreadCreateFirst;
extern "C" void PearThreadCreateFailed(uint32_t Stage,uint64_t Context,uint64_t Thread,uint64_t Slot,
                                       uint32_t Status,uint32_t Domain,int32_t Code) {
  if (!PearPhaseOptIn || !PearEntryObserve || !PearPhasePID) return;
  // GetCurrentThreadId reads the current TEB; no source Thread is dereferenced.
  PearThreadCreateFirst.Capture({PearPhasePID,GetCurrentThreadId(),Context,Thread,Slot,Stage,Status,Domain,Code});
}
extern "C" bool PearAttachObservationEnabled() {
  return PearPhaseOptIn && PearEntryObserve && PearPhasePID;
}
extern "C" void PearThreadCreateAttachFailed(uint64_t Context,uint64_t Thread,uint64_t Slot,
    uint32_t Status,uint32_t Domain,int32_t Code,const PearAttach::Diagnostic* Diag) {
  if (!PearAttachObservationEnabled()) return;
  PearThreadCreate::Record r {PearPhasePID,GetCurrentThreadId(),Context,Thread,Slot,5,Status,Domain,Code};
  if (Diag && Diag->Status==Status && Diag->Domain==Domain && Diag->Code==Code) r.Attach=*Diag;
  PearThreadCreateFirst.Capture(r);
}
static void PearThreadCreateReport(const void* Context,const PearMemory::Result* Primary,
                                   const PearMemory::Result& Cleanup,bool CleanupAttempted,bool ReadyBefore) {
  if (!PearPhaseOptIn || !PearEntryObserve) return;
  const auto Output=PearCheckpointSink.load(std::memory_order_acquire);
  if (!Output) return;
  PearThreadCreate::Record r;
  if (!PearThreadCreateFirst.Take(PearPhasePID,GetCurrentThreadId(),reinterpret_cast<uint64_t>(Context),
                                  reinterpret_cast<uint64_t>(Primary),r)) return;
  const int SavedErrno=errno; const DWORD SavedError=GetLastError();
  char Text[640];
  // call=1 is the captured failure ordinal, not the number of ThreadInit calls.
  // A source lifetime has not necessarily been created; do not invent one.
  snprintf(Text,sizeof(Text),"PEAR_CREATE1 pid=%llu tid=%llu call=1 stage=%u context=%llx thread=%llx slot=%llx life=0 life_known=0 status=%u domain=%u code=%d returned_status=%u returned_domain=%u returned_code=%d cleanup_attempted=%u cleanup_status=%u cleanup_domain=%u cleanup_code=%d ready_before=%u ready_after=%u\n",
    (unsigned long long)r.Process,(unsigned long long)r.ThreadID,r.Stage,(unsigned long long)r.Context,
    (unsigned long long)r.Thread,(unsigned long long)r.OutcomeSlot,r.Status,r.Domain,r.Code,
    Primary->Status,Primary->ErrorDomain,Primary->ErrorCode,CleanupAttempted?1u:0u,
    Cleanup.Status,Cleanup.ErrorDomain,Cleanup.ErrorCode,ReadyBefore?1u:0u,
    PearSourceReady.load(std::memory_order_acquire)?1u:0u);
  Output(Text);
  if (r.Stage==5 && r.Attach.Where!=PearAttach::Branch::Unknown) {
    snprintf(Text,sizeof(Text),"PEAR_ATTACH1 pid=%llu tid=%llu call=1 context=%llx thread=%llx slot=%llx branch=%u first=%u flags=%u context_serial=%llu binding_serial=%llu status=%u domain=%u code=%d intermediate_status=%u intermediate_domain=%u intermediate_code=%d\n",
      (unsigned long long)r.Process,(unsigned long long)r.ThreadID,(unsigned long long)r.Context,
      (unsigned long long)r.Thread,(unsigned long long)r.OutcomeSlot,uint32_t(r.Attach.Where),uint32_t(r.Attach.FirstFailure),
      r.Attach.Flags,(unsigned long long)r.Attach.ContextSerial,(unsigned long long)r.Attach.BindingSerial,
      r.Attach.Status,r.Attach.Domain,r.Attach.Code,r.Attach.IntermediateStatus,r.Attach.IntermediateDomain,r.Attach.IntermediateCode);
    Output(Text);
  }
  if (r.Stage==5 && r.Attach.Where==PearAttach::Branch::BindCapacity) PearBindings::Emit(r,Output);
  SetLastError(SavedError);errno=SavedErrno;
}
#endif
