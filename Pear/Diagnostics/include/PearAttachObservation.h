// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
#include "PearBindingCensus.h"

namespace PearAttach {
enum class Branch : uint16_t {
  Unknown, InvalidArguments, OuterAdmission, ExistingPrior, ExistingIdentity,
  SameThreadRole, SameThreadIdleOrFinish, BootstrapUnregister,
  BootstrapTransferIdentity, BindAdmission, BindIdentity, BindExistingIdentity,
  BindCapacity, RegisterAdmission, RegisterPrecheck, RegisterInvoke,
  RegisterResponseShape, RegisterFinishIdentity
};
enum : uint32_t {
  ContextKnown=1, BindingKnown=2, BridgeFactsKnown=4,
  BridgeCalled=8, ValidatedRefusal=16, CleanupCandidateKnown=32,
  NoEmptyBinding=64, SerialExhausted=128, CapacityKnown=256,
  IntermediateKnown=512
};
// Caller-stack metadata only. Serial observations do not grant a lifetime hold.
struct Diagnostic {
  Branch Where {}, FirstFailure {};
  uint32_t Flags {}, Status {}, Domain {};
  int32_t Code {};
  uint32_t IntermediateStatus {}, IntermediateDomain {};
  int32_t IntermediateCode {};
  uint64_t ContextSerial {}, BindingSerial {};
  PearBindings::Snapshot Census {};
};
inline void ClearIdentities(Diagnostic* d) {
  if (d) {
    d->Flags&=~(ContextKnown|BindingKnown);
    d->ContextSerial=0; d->BindingSerial=0;
  }
}
template<class Result>
Result Capture(Diagnostic* d, Branch where, Result result) {
  if (d && !result) {
    if (d->FirstFailure==Branch::Unknown) d->FirstFailure=where;
    d->Where=where; d->Status=result.Status;
    d->Domain=result.ErrorDomain; d->Code=result.ErrorCode;
  }
  return result;
}
template<class Result>
void Intermediate(Diagnostic* d, Result result) {
  if (d) {
    d->IntermediateStatus=result.Status; d->IntermediateDomain=result.ErrorDomain;
    d->IntermediateCode=result.ErrorCode; d->Flags|=IntermediateKnown;
  }
}
static_assert(sizeof(Diagnostic)<=6144);
}
namespace FEXCore::Context { class Context; }
namespace FEXCore::Core { struct InternalThreadState; }
namespace FEXCore::Utils::PearFEXMemory {
struct Result;
Result AttachAllocatedThreadObserved(const FEXCore::Context::Context*,
  FEXCore::Core::InternalThreadState*,uint32_t,PearAttach::Diagnostic*);
}
extern "C" bool PearAttachObservationEnabled();
