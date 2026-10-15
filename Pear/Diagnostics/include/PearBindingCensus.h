// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
#include <cstddef>
namespace PearBindings {
// Private diagnostic metadata, never owner ABI or a native-liveness assertion.
constexpr uint32_t Capacity=64;
struct Row {
  uint64_t TEB {}, WindowsTid {}, Source {}, Context {}, Attempt {}, Executor {}, Serial {};
  uint32_t Flags {}, Holds {}, Role {}, Kind {}, Transition {}, ActiveKind {}, OriginalStatus {}, CleanupStatus {};
};
struct Snapshot {
  uint64_t NextSerial {};
  uint32_t Count {}, Occupied {};
  Row Rows[Capacity] {};
};
// Caller holds the existing RegistryGuard. Copy values only: no dereference of
// recorded identities, allocation, OS call, bridge call, output or policy action.
template<class Binding,size_t N>
void Copy(Snapshot& out,const Binding (&bindings)[N],uint64_t nextSerial) {
  static_assert(N==Capacity);
  out.Count=0;out.Occupied=0;out.NextSerial=nextSerial;
  for (size_t i=0;i<N;++i) {
    const auto& b=bindings[i];auto& r=out.Rows[i];
    r.TEB=reinterpret_cast<uint64_t>(b.TEB);r.WindowsTid=b.NativeThread;
    r.Source=reinterpret_cast<uint64_t>(b.SourceState);
    r.Context=reinterpret_cast<uint64_t>(b.SourceContext);
    r.Attempt=reinterpret_cast<uint64_t>(b.AttachAttempt);
    r.Executor=b.Executor;r.Serial=b.LifetimeSerial;
    r.Flags=(b.Pending?1u:0u)|(b.Capturing?2u:0u)|(b.Unresolved?4u:0u)|
      (b.CleanupAttempted?8u:0u)|(b.LifetimeClosing?16u:0u)|
      (b.LifetimeDeleteSealed?32u:0u)|(b.CleanupOnly?64u:0u);
    r.Holds=b.LifetimeHolds;r.Role=b.Role;r.Kind=uint32_t(b.SourceKind);
    r.Transition=uint32_t(b.Transition);r.ActiveKind=uint32_t(b.Active.Kind);
    r.OriginalStatus=b.OriginalFailure.Status;r.CleanupStatus=b.CleanupOutcome.Status;
    if (b.TEB) ++out.Occupied;
  }
  out.Count=Capacity;
}
static_assert(sizeof(Row)==88);
static_assert(sizeof(Snapshot)<=6144);
}
