// SPDX-FileCopyrightText: 2026 Pear contributors
// SPDX-License-Identifier: MIT
// Adapted from PearThreadCreateRuntime.inc: same opt-ins and resolved sink.
#include "PearSlotLifetime.h"
namespace PearSlot {
static std::atomic<uint32_t> NextCall {};
static std::atomic<bool> LossEmitted {};
static_assert(std::atomic<uint32_t>::is_always_lock_free);
static_assert(std::atomic<bool>::is_always_lock_free);
static void Loss(unsigned reason) {
  if (LossEmitted.exchange(true,std::memory_order_relaxed)) return;
  const int savedErrno=errno; const DWORD savedError=GetLastError();
  const auto output=PearCheckpointSink.load(std::memory_order_acquire);
  if (output) {
    char text[128];
    snprintf(text,sizeof(text),"PEAR_SLOT_LOSS1 pid=%llu limit=512 reason=%u\n",
      (unsigned long long)PearPhasePID,reason); output(text);
  }
  SetLastError(savedError); errno=savedErrno;
}
uint64_t Begin() {
  if (!PearEntryObserve || !PearPhaseOptIn || !PearPhasePID ||
      !PearCheckpointSink.load(std::memory_order_acquire)) return 0;
  auto next=NextCall.load(std::memory_order_relaxed);
  for (unsigned retry=0;retry<4;++retry) {
    if (next>=512) { Loss(1); return 0; }
    if (NextCall.compare_exchange_weak(next,next+1,std::memory_order_relaxed)) return next+1;
  }
  Loss(2); return 0; // Bounded contention loss, never wait or reuse a ticket.
}
void Emit(const Event& e) {
  const int savedErrno=errno; const DWORD savedError=GetLastError();
  const auto output=PearCheckpointSink.load(std::memory_order_acquire);
  if (output) {
    char text[768];
    int n=snprintf(text,sizeof(text),"PEAR_SLOT1 pid=%llu tid=%lu call=%llu stage=%u side=%u context=%llx source=%llx serial=%llu snapshot=%u row_context=%llx row_source=%llx row_serial=%llu executor=%llu holds=%u flags=%u kind=%u status=%u domain=%u code=%d returned=%u destroyed=%u freed=%u bridge_called=%u validated=%u\n",
      (unsigned long long)PearPhasePID,(unsigned long)GetCurrentThreadId(),
      (unsigned long long)e.Call,e.Stage,e.Side,(unsigned long long)e.Context,
      (unsigned long long)e.Source,(unsigned long long)e.Serial,e.Current.Snapshot,
      (unsigned long long)e.Current.Context,(unsigned long long)e.Current.Source,
      (unsigned long long)e.Current.Serial,(unsigned long long)e.Current.Executor,
      e.Current.Holds,e.Current.Flags,e.Kind,e.Status,e.Domain,e.Code,e.Returned,
      e.Destroyed,e.Freed,e.BridgeCalled,e.Validated);
    if (n>0 && static_cast<size_t>(n)<sizeof(text)) output(text); else Loss(3);
  }
  SetLastError(savedError); errno=savedErrno;
}
}
