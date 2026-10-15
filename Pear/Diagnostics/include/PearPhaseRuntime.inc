// SPDX-License-Identifier: MIT
// Included after the existing checkpoint sink. Selection is private generated
// data, pinned by the candidate build record, never embedded in public sources.
#ifdef PEAR_PHASE_OBSERVE
#include "PearPhaseSelection.h"
static PearPhase::Recorder<> PearPhaseRecords;
static std::atomic<uint64_t> PearPhaseBase {}, PearPhaseGeneration {};
static uint64_t PearPhaseSize {};
static bool PearPhaseOptIn {};
static uint32_t PearPhasePID {};
extern "C" bool PearPhaseEnabled() { return PearPhaseOptIn; }
extern "C" const void* PearPhaseActiveAddress() { return PearPhaseRecords.ActiveAddress(); }
extern "C" bool PearPhaseSelected(uint64_t PC) {
  if (!PearPhaseOptIn) return false;
  const auto Base=PearPhaseBase.load(std::memory_order_acquire);
  if (!Base || PC<Base) return false;
  for (const auto& m:PearPhaseMarkers) if (PC-Base==m.RVA) return true;
  return false;
}
// SEH covers only this bounded copy, never the observer's bookkeeping or a game
// operation. An unreadable diagnostic value is unknown, not game success.
extern "C" bool PearPhaseCopy(void*,uint64_t,size_t);
static void PearPhaseMap(uint64_t Address, const char* Name) {
  if (!PearPhaseOptIn || _stricmp(Name,"GameAssembly.dll")) return;
  if (PearPhaseBase.load(std::memory_order_acquire)==Address) return;
  const auto Old=PearPhaseBase.exchange(0,std::memory_order_acq_rel);
  if (Old) PearPhaseRecords.EndModule(PearPhaseGeneration.load(std::memory_order_relaxed));
  unsigned char bytes[16];
  for (const auto& m:PearPhaseMarkers) {
    if (Address>UINT64_MAX-m.RVA || !PearPhaseCopy(bytes,Address+m.RVA,16) || std::memcmp(bytes,m.Bytes,16)) {
      PearPhaseRecords.MarkLoss(PearPhase::Invalid); return;
    }
  }
  PearPhaseSize=PearPhaseImageSize;
  const auto Generation=PearPhaseGeneration.fetch_add(1,std::memory_order_relaxed)+1;
  PearPhaseRecords.BeginModule(Generation,Address,PearPhaseSize);
  PearPhaseBase.store(Address,std::memory_order_release);
}
static void PearPhaseUnmap(uint64_t Address,uint64_t Size) {
  const auto Base=PearPhaseBase.load(std::memory_order_acquire);
  if (!Base || !Size || Address>UINT64_MAX-Size || Base>UINT64_MAX-PearPhaseSize) return;
  if (Address<Base+PearPhaseSize && Address+Size>Base) {
    PearPhaseBase.store(0,std::memory_order_release);
    PearPhaseRecords.EndModule(PearPhaseGeneration.load(std::memory_order_relaxed));
  }
}
extern "C" void PearPhaseExecuted(FEXCore::Core::CpuStateFrame* Frame,uint64_t PC,uint64_t IsMarker) {
  if (!PearPhaseOptIn || !PearPhaseBase.load(std::memory_order_acquire)) return;
  const auto Area=GetCPUArea(); auto* Thread=Area.ThreadState();
  if (!Area.Area || !Thread || Thread->CurrentFrame!=Frame || Area.StateFrame()!=Frame || !Thread->FrontendPtr) {
    PearPhaseRecords.MarkLoss(PearPhase::Invalid); return;
  }
  const int SavedErrno=errno; const DWORD SavedError=GetLastError();
  ScopedCallbackDisable Callback;
  auto* Frontend=GetFrontendThreadData(Thread);
  PearPhase::Context c {};
  c.Thread=GetCurrentThreadId();c.Lifetime=Frontend->PhaseLifetime;
  c.Generation=PearPhaseGeneration.load(std::memory_order_acquire);c.PC=PC;
  c.SP=Frame->State.gregs[FEXCore::X86State::REG_RSP];
  c.Object=Frame->State.gregs[FEXCore::X86State::REG_RCX];
  c.Arg1=Frame->State.gregs[FEXCore::X86State::REG_RDX];
  c.Value=Frame->State.gregs[FEXCore::X86State::REG_RAX];
  if (PearPhaseRecords.WantsName(c)) {
    int32_t Length {};
    if (c.Value && c.Value<=UINT64_MAX-20 && PearPhaseCopy(&Length,c.Value+16,4) && Length>0 && Length<=48 &&
        PearPhaseCopy(c.ReturnedName.Text.data(),c.Value+20,static_cast<size_t>(Length)*2)) {
      c.ReturnedName.Size=Length;c.ReturnedName.Valid=true;
    }
  }
  PearPhaseRecords.Execute(c);
  if (IsMarker) {
    const auto Base=PearPhaseBase.load(std::memory_order_acquire);
    for (const auto& m:PearPhaseMarkers) if (Base && PC>=Base && PC-Base==m.RVA) {
      if (m.Kind==PearPhase::Kind::FunctionEntry || m.Kind==PearPhase::Kind::SceneNameEntry)
        c.ReturnReadable=PearPhaseCopy(&c.ReturnPC,c.SP,8);
      PearPhaseRecords.Marker(c,m.Kind,m.ID);break;
    }
  }
  SetLastError(SavedError);errno=SavedErrno;
}
// Existing EC transition/checkpoint boundary drains after the source lifetime
// is explicitly released. No formatting, logging or loader operation in JIT.
static void PearPhaseDrain() {
  if (!PearPhaseOptIn) return;
  const auto Output=PearCheckpointSink.load(std::memory_order_acquire); if (!Output) return;
  const int SavedErrno=errno; const DWORD SavedError=GetLastError();
  PearPhase::Record r;char Text[768],Name[193];
  for (unsigned count=0;count<16 && PearPhaseRecords.Take(r);++count) {
    unsigned at=0;
    if (r.SceneName.Valid) for (unsigned i=0;i<r.SceneName.Size;++i)
      at+=snprintf(Name+at,sizeof(Name)-at,"%04x",static_cast<unsigned>(r.SceneName.Text[i]));
    Name[at]=0;
    snprintf(Text,sizeof(Text),"PEAR_PHASE1 seq=%llu pid=%lu tid=%llu life=%llu gen=%llu inv=%llu event=%u kind=%u marker=%u pc=%llx sp=%llx obj=%llx arg1=%llx value=%llx entry=%llx ret=%llx esp=%llx loss=%u name=%s\n",
      (unsigned long long)r.Sequence,(unsigned long)PearPhasePID,(unsigned long long)r.Thread,(unsigned long long)r.Lifetime,
      (unsigned long long)r.Generation,(unsigned long long)r.Invocation,static_cast<unsigned>(r.Type),
      static_cast<unsigned>(r.Source),r.Marker,(unsigned long long)r.PC,(unsigned long long)r.SP,
      (unsigned long long)r.Object,(unsigned long long)r.Arg1,(unsigned long long)r.Value,
      (unsigned long long)r.EntryPC,(unsigned long long)r.ReturnPC,(unsigned long long)r.EntrySP,
      PearPhaseRecords.LossFlags(),Name);
    Output(Text);
  }
  static std::atomic<uint32_t> LastLoss {};
  const auto Loss=PearPhaseRecords.LossFlags();
  if (Loss!=LastLoss.exchange(Loss,std::memory_order_relaxed)) {
    snprintf(Text,sizeof(Text),"PEAR_PHASE_STATUS1 pid=%lu loss=%u\n",(unsigned long)PearPhasePID,Loss);Output(Text);
  }
  SetLastError(SavedError);errno=SavedErrno;
}
#endif
