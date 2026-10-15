// SPDX-License-Identifier: MIT
#pragma once
#include <atomic>
#include <cstdint>
#include "PearAttachObservation.h"

namespace PearThreadCreate {
struct Record {
  uint64_t Process {}, ThreadID {}, Context {}, Thread {}, OutcomeSlot {};
  uint32_t Stage {}, Status {}, Domain {};
  int32_t Code {};
  PearAttach::Diagnostic Attach {};
};
// One captured failing invocation per process. No allocation, wait or output in
// a source/owner critical section. Missing records never establish success.
class Recorder {
  std::atomic<uint32_t> State {};
  Record First {};
public:
  bool Capture(const Record& r) {
    if (!r.Process || !r.ThreadID || !r.Context || !r.OutcomeSlot ||
        r.Stage<1 || r.Stage>7 || !r.Status || r.Status>8) return false;
    uint32_t expected=0;
    if (!State.compare_exchange_strong(expected,1,std::memory_order_acquire)) return false;
    First=r;
    State.store(2,std::memory_order_release);
    return true;
  }
  bool Take(uint64_t process,uint64_t tid,uint64_t context,uint64_t slot,Record& out) {
    if (State.load(std::memory_order_acquire)!=2) return false;
    if (First.Process!=process || First.ThreadID!=tid || First.Context!=context || First.OutcomeSlot!=slot) return false;
    uint32_t expected=2;
    if (!State.compare_exchange_strong(expected,3,std::memory_order_acq_rel)) return false;
    out=First;
    return true;
  }
};
static_assert(std::atomic<uint32_t>::is_always_lock_free);
static_assert(sizeof(Recorder)<=6144);
}
