// SPDX-License-Identifier: MIT
// Original bounded source link tickets; actual descriptors are minted only by
// the retained-source JIT caller, never from arbitrary wire/guest metadata.
#pragma once
#include "Interface/Core/PearJITLinkLayout.h"
#include "Interface/Core/PearJITLinkTickets.h"
#include <FEXCore/Utils/PearFEXLinks.h>
#include <FEXCore/Utils/PearFEXRetirement.h>
#include <array>
#include <optional>

namespace FEXCore::CPU {
class Arm64JITCore;
namespace PearJITLinks {
struct Registry;
class SourceDescriptor {
public:
  explicit operator bool() const { return Owner && SourceContext && AllocationID && Generation && OwnerPID; }
private:
  friend class FEXCore::CPU::Arm64JITCore;
  friend struct Registry;
  friend std::optional<TicketLedger::Ticket> Prepare(SourceDescriptor);
  friend FEXCore::Utils::PearFEXMemory::Result PatchPrepared(TicketLedger::Ticket,FEXCore::Core::InternalThreadState*,uint64_t);
  friend FEXCore::Utils::PearFEXMemory::Result Queue(TicketLedger::Ticket);
  friend FEXCore::Utils::PearFEXMemory::Result BeginBatch(FEXCore::Context::ContextImpl*,FEXCore::Core::InternalThreadState*);
  friend FEXCore::Utils::PearFEXMemory::Result FinishBatch(FEXCore::Context::ContextImpl*,FEXCore::Core::InternalThreadState*);
  friend bool FEXCore::Utils::PearFEXMemory::Links::HasOutstanding(const FEXCore::Context::Context*);
  SourceDescriptor(fextl::shared_ptr<CodeBuffer> ActualOwner, FEXCore::Context::ContextImpl* ActualContext,
                   const FEXCore::Utils::PearFEXMemory::Allocation& ActualPublished,
                   const PearJITLinkLayout::Layout& ActualLayout, const PearJITLinkLayout::Instructions& Encoded,
                   const std::array<uint8_t,PearJITLinkLayout::THUNK_BYTES>& ActualThunk,
                   const std::array<uint8_t,PearJITLinkLayout::CALLER_BYTES>& ActualCaller,
                   uint64_t ActualGuestDestination, uintptr_t ActualHostDestination)
    : Owner(std::move(ActualOwner)), SourceContext(ActualContext), AllocationID(ActualPublished.Token.allocation_id),
      Generation(ActualPublished.Token.generation), OwnerPID(ActualPublished.Token.owner_pid), Layout(ActualLayout),
      Instructions(Encoded), Thunk(ActualThunk), Caller(ActualCaller), GuestDestination(ActualGuestDestination), HostDestination(ActualHostDestination) {}
  fextl::shared_ptr<CodeBuffer> Owner;
  FEXCore::Context::ContextImpl* SourceContext {};
  uint64_t AllocationID {}, Generation {}, OwnerPID {};
  PearJITLinkLayout::Layout Layout;
  PearJITLinkLayout::Instructions Instructions;
  std::array<uint8_t,PearJITLinkLayout::THUNK_BYTES> Thunk;
  std::array<uint8_t,PearJITLinkLayout::CALLER_BYTES> Caller;
  uint64_t GuestDestination {};
  uintptr_t HostDestination {};
};
using Ticket = TicketLedger::Ticket;
std::optional<Ticket> Prepare(SourceDescriptor);
FEXCore::Utils::PearFEXMemory::Result PatchPrepared(Ticket, FEXCore::Core::InternalThreadState*, uint64_t SourceRevision);
FEXCore::Utils::PearFEXMemory::Result Commit(Ticket);
FEXCore::Utils::PearFEXMemory::Result CancelPrepared(Ticket);
// Begin before actual guest mutation/locking. This marker is not quiescence;
// the caller still obtains a real owned target WriteGuard at its native gate.
FEXCore::Utils::PearFEXMemory::Result BeginBatch(FEXCore::Context::ContextImpl*, FEXCore::Core::InternalThreadState*);
FEXCore::Utils::PearFEXMemory::Result Queue(Ticket);
FEXCore::Utils::PearFEXMemory::Result FinishBatch(FEXCore::Context::ContextImpl*, FEXCore::Core::InternalThreadState*);
} // namespace PearJITLinks
} // namespace FEXCore::CPU
