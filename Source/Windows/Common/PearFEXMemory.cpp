#include "PearSlotLifetime.h"
#include "PearAttachObservation.h"
#include "PearWriterObservation.h"
#include "PearTargetObservation.h"
#include "PearAbortObservation.h"
// SPDX-License-Identifier: MIT
// Original Pear adapter; the exact Wine wire header is the ABI authority.
#include <FEXCore/Utils/PearFEXMemory.h>
#include <FEXCore/Utils/PearFEXRetirement.h>
#include <FEXCore/Utils/PearFEXLinks.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <atomic>
#include <cstdlib>
#include <FEXCore/Utils/LogManager.h>
#include <cstring>
#include <limits>
#include <ntstatus.h>
#include <windef.h>
#include <winbase.h>
#define __WINESRC__
#include <winternl.h>
#include <libloaderapi.h>
#include "Priv.h"

#ifdef ARCHITECTURE_arm64ec
// Reuse the actual ntdll CHPE table populated by Module::InitSyscalls before
// owner initialization. Exports point to x64 fast-forward stubs, not raw ARM64.
extern "C" {
extern uintptr_t NtDllBase;
extern uint32_t* NtDllRedirectionLUT;
extern uint32_t NtDllRedirectionLUTSize;
}
#endif

// One diagnostic scope process-wide. A single failed CAS means unavailable.
// No TLS, waiting, allocation, retained output-record pointer or memory policy decision.
struct PearReadIdentitySlot {
  PearReadIdentity value {};
  const void* thread {};
  const void* dest {};
  size_t offset {},bytes {};
  uint64_t ticket {};
};
static PearReadIdentitySlot PearReadIdentityActive {};
static std::atomic<bool> PearReadIdentityBusy {};
static std::atomic<uintptr_t> PearReadIdentityOwner {};
static uint64_t PearReadIdentityNext {};
static std::atomic<bool> PearReadIdentityLost {};
static_assert(std::atomic<bool>::is_always_lock_free);
static_assert(std::atomic<uintptr_t>::is_always_lock_free);
struct PearReadIdentityGuard {
  bool owned {};
  PearReadIdentityGuard() {
    bool expected=false;
    owned=PearReadIdentityBusy.compare_exchange_strong(expected,true,std::memory_order_acquire);
  }
  ~PearReadIdentityGuard(){if(owned)PearReadIdentityBusy.store(false,std::memory_order_release);}
  PearReadIdentityGuard(const PearReadIdentityGuard&)=delete;
  PearReadIdentityGuard& operator=(const PearReadIdentityGuard&)=delete;
};
static uintptr_t PearReadIdentitySelf(){return reinterpret_cast<uintptr_t>(GetCurrentTEB());}
extern "C" uint64_t PearReadIdentityBegin(const void* thread,const void* dest,size_t offset,size_t bytes) {
  if (!thread || !dest || bytes!=52) return 0;
  PearReadIdentityGuard lock;
  if (!lock.owned) { PearReadIdentityLost.store(true,std::memory_order_relaxed);return 0; }
  const auto self=PearReadIdentitySelf();if(!self)return 0;
  const auto owner=PearReadIdentityOwner.load(std::memory_order_relaxed);
  if (owner) {
    // A rejected nested scope must not let its identical-range read fill the outer record.
    if(owner==self)PearReadIdentityLost.store(true,std::memory_order_relaxed);
    return 0;
  }
  if(PearReadIdentityNext==UINT64_MAX)return 0;
  PearReadIdentityActive={{},thread,dest,offset,bytes,++PearReadIdentityNext};
  PearReadIdentityLost.store(false,std::memory_order_relaxed);
  PearReadIdentityOwner.store(self,std::memory_order_release);
  return PearReadIdentityActive.ticket;
}
extern "C" void PearReadIdentityEnd(uint64_t ticket,PearReadIdentity* out) {
  if(!ticket || !out || !PearReadIdentityOwner.load(std::memory_order_acquire))return;
  PearReadIdentityGuard lock;
  if(!lock.owned || PearReadIdentityOwner.load(std::memory_order_relaxed)!=PearReadIdentitySelf() ||
     PearReadIdentityActive.ticket!=ticket)return;
  *out=PearReadIdentityActive.value;
  if(PearReadIdentityLost.load(std::memory_order_relaxed))out->seen=2;
  PearReadIdentityActive={};PearReadIdentityOwner.store(0,std::memory_order_release);
}

static PearWriterRecorder PearWriterRing {};
static void PearWriterReadCut(const void* thread,const void* dest,size_t offset,size_t bytes) {
  if(bytes!=52 || !PearReadIdentityOwner.load(std::memory_order_acquire))return;
  PearReadIdentityGuard lock;
  if(!lock.owned){PearReadIdentityLost.store(true,std::memory_order_relaxed);return;}
  if(PearReadIdentityOwner.load(std::memory_order_relaxed)!=PearReadIdentitySelf() ||
     PearReadIdentityLost.load(std::memory_order_relaxed))return;
  auto& s=PearReadIdentityActive;
  if(s.thread!=thread || s.dest!=dest || s.offset!=offset || s.bytes!=bytes)return;
  auto& value=s.value;
  if(value.writer_seen){value.writer_seen=2;return;}
  const auto cut=PearWriterRing.Cut();
  value.writer_seen=cut.seen;value.writer_cut=cut.sequence;value.writer_loss=cut.lost;
}

namespace FEXCore::Utils::PearFEXMemory {
namespace {
using BridgeType = uint32_t(WINAPI*)(const pear_fex_memory_request*, pear_fex_memory_response*);
static BridgeType BridgeDirect {};
static uint64_t OwnerPID {};
static std::atomic<bool> Configured {false};
enum class LeaseKind : uint32_t { None, Active, Pinned, Unresolved };
enum class PendingTransition : uint32_t { Unknown, Entry, Exit, Handoff, Poll, Resume, Unpin, Unregister };
struct ActiveLease {
  Allocation Target {};
  const void* TEB {};
  uintptr_t NativeThread {};
  const void* SourceState {};
  uint64_t Executor {};
  size_t EntryOffset {};
  uint64_t Continuation {};
  LeaseKind Kind {LeaseKind::None};
};
struct Binding {
  enum class Kind : uint32_t { None, Bootstrap, Thread } SourceKind {};
  const void* TEB {};
  uintptr_t NativeThread {};
  const void* SourceState {};
  const FEXCore::Context::Context* SourceContext {};
  const FEXCore::Core::InternalThreadState* AttachAttempt {};
  uint64_t Executor {};
  uint32_t Role {};
  bool Pending {};
  PendingTransition Transition {};
  bool Capturing {};
  bool Unresolved {};
  bool CleanupAttempted {};
  Result OriginalFailure {PEAR_FEX_OK, 0, 0};
  Result CleanupOutcome {};
  ActiveLease Active {};
  uint64_t LifetimeSerial {};
  uint32_t LifetimeHolds {};
  bool LifetimeClosing {}, LifetimeDeleteSealed {}, CleanupOnly {};
};
static Binding Bindings[PEAR_FEX_MEMORY_MAX_EXECUTORS] {};
struct ContextLifetime {
  const FEXCore::Context::Context* Object {};
  uint64_t Serial {};
  uint32_t Holds {};
  const void* CreationTEB {};
  uintptr_t CreationNativeThread {};
  bool Closing {}, DeleteSealed {}, Retained {}, DestroyedBacking {}, DeletionStarted {};
};
// Each selected Windows module owns exactly one process-wide CTX. Refuse a
// second admitted Context in this module; no speculative 64-Context budget.
static constexpr uint32_t SOURCE_CONTEXT_CAPACITY=1;
static ContextLifetime ContextLifetimes[SOURCE_CONTEXT_CAPACITY] {};
static uint64_t NextLifetimeSerial {};
static ContextLifetime* ContextRecord(const FEXCore::Context::Context* Object) {
  for (auto& C:ContextLifetimes) if (C.Object == Object && Object) return &C;
  return nullptr;
}
static std::atomic<uintptr_t> Registry {0};
static std::atomic<uint64_t> MutationExecutor {0};
static std::atomic<uint32_t> MutationSequence {0};
// D5 diagnostics have no owner authority. The mutation buffer has the same
// exclusive writer as MutationExecutor; peer checkpoints are single atomic words.
struct WakePeer {
  uint64_t Executor {}, Serial {};
  uint32_t Index {}, Role {}, Lease {}, Flags {}, DoorbellBefore {};
};
struct WakeScan {
  uint64_t Writer {};
  uint32_t Epoch {}, Writing {}, NestedWriting {}, Count {};
  WakePeer Peers[PEAR_FEX_MEMORY_MAX_EXECUTORS] {};
};
static std::atomic<bool> WakeEnabled {false};
static std::atomic<uint32_t> WakeEpoch {};
static std::atomic<uint64_t> WakeCheckpoints[PEAR_FEX_MEMORY_MAX_EXECUTORS] {};
static WakeScan WakeSnapshot {};
static uint32_t WakeNextEpoch {}, WakeDumps {};
static_assert(std::atomic<uint64_t>::is_always_lock_free);
static_assert(sizeof(WakeSnapshot)+sizeof(WakeCheckpoints)+sizeof(WakeEpoch)+
              sizeof(WakeEnabled)+sizeof(WakeNextEpoch)+sizeof(WakeDumps) <= 4096);
static void BeginWakeScan(uint64_t Writer, bool Writing) {
  if (!WakeEnabled.load(std::memory_order_relaxed)) return;
  WakeSnapshot = {};
  WakeSnapshot.Writer = Writer; WakeSnapshot.Writing = Writing;
  // Exhaustion disables attribution; never wrap a correlation identity.
  if (WakeNextEpoch != UINT32_MAX) WakeSnapshot.Epoch = ++WakeNextEpoch;
  WakeEpoch.store(WakeSnapshot.Epoch, std::memory_order_release);
}
static WakePeer* CaptureWakePeer(const Binding& Peer) {
  if (!WakeEnabled.load(std::memory_order_relaxed) || !Peer.Executor || Peer.Executor==WakeSnapshot.Writer) return nullptr;
  if (WakeSnapshot.Count >= PEAR_FEX_MEMORY_MAX_EXECUTORS) return nullptr;
  auto& Row=WakeSnapshot.Peers[WakeSnapshot.Count++];
  Row.Executor=Peer.Executor; Row.Serial=Peer.LifetimeSerial;
  Row.Index=static_cast<uint32_t>(&Peer-Bindings); Row.Role=Peer.Role; Row.Lease=static_cast<uint32_t>(Peer.Active.Kind);
  Row.Flags=(Peer.SourceKind==Binding::Kind::Thread ? 1U:0U) | (Peer.Role==PEAR_FEX_ROLE_ARM64EC ? 2U:0U) |
    (Peer.Active.Kind==LeaseKind::Active ? 4U:0U) | (Peer.LifetimeClosing ? 8U:0U) |
    (Peer.LifetimeDeleteSealed ? 16U:0U) | (Peer.Unresolved ? 32U:0U) |
    (Peer.Pending ? 2048U:0U) | (Peer.Capturing ? 4096U:0U);
  return &Row;
}
// Epoch/serial/phase/status fit one release/acquire word: no torn attribution,
// reader retry, per-event allocation or peer lock. Missing/overflow is unknown.
static void RecordWakeCheckpoint(uint32_t Index, uint64_t Serial, unsigned Phase, Result Outcome) {
  if (!WakeEnabled.load(std::memory_order_relaxed) || Index>=PEAR_FEX_MEMORY_MAX_EXECUTORS ||
      !Serial || Serial>UINT16_MAX || !Phase || Phase>6 || Outcome.Status>UINT8_MAX) return;
  const auto Epoch=WakeEpoch.load(std::memory_order_acquire);
  if (!Epoch) return;
  const uint64_t Word=(uint64_t(Epoch)<<32) | (Serial<<16) | (uint64_t(Phase)<<8) | Outcome.Status;
  WakeCheckpoints[Index].store(Word,std::memory_order_release);
}
static uint64_t MatchedWakeCheckpoint(const WakePeer& Peer, uint32_t Epoch) {
  if (!Epoch || !Peer.Serial || Peer.Serial>UINT16_MAX || Peer.Index>=PEAR_FEX_MEMORY_MAX_EXECUTORS) return 0;
  const auto Word=WakeCheckpoints[Peer.Index].load(std::memory_order_acquire);
  return uint32_t(Word>>32)==Epoch && ((Word>>16)&UINT16_MAX)==Peer.Serial ? Word : 0;
}
static void ObserveWakeFailure(uint64_t Writer) {
  if (!WakeEnabled.load(std::memory_order_relaxed) || !Writer ||
      MutationExecutor.load(std::memory_order_acquire)!=Writer || WakeSnapshot.Writer!=Writer || WakeDumps>=8) return;
  const auto Sequence=WakeDumps++;
  LogMan::Msg::EFmt("PEAR_WAKE seq={} writer={} epoch={} writing={} nested={} rows={}",
    Sequence,Writer,WakeSnapshot.Epoch,WakeSnapshot.Writing,WakeSnapshot.NestedWriting,WakeSnapshot.Count);
  for (uint32_t I=0;I<WakeSnapshot.Count;++I) {
    const auto& P=WakeSnapshot.Peers[I]; const auto Word=MatchedWakeCheckpoint(P,WakeSnapshot.Epoch);
    LogMan::Msg::EFmt("PEAR_WAKE_PEER seq={} index={} id={} serial={} role={} lease={} flags={} before={} checkpoint={} phase={} status={}",
      Sequence,I,P.Executor,P.Serial,P.Role,P.Lease,P.Flags,P.DoorbellBefore,unsigned(Word!=0),unsigned((Word>>8)&255),unsigned(Word&255));
  }
}

static_assert(sizeof(Bindings) + sizeof(ContextLifetimes) + sizeof(NextLifetimeSerial) + sizeof(Registry) + sizeof(MutationExecutor) + sizeof(MutationSequence) + sizeof(BridgeDirect) + sizeof(OwnerPID) + sizeof(Configured) <= 24576,
              "Bounded source adapter NX metadata, typed bindings and retained registration failures");
// This local bound is part of, not a substitute for, the compiled aggregate
// 256-KiB owner/adapter/holder/descriptor metadata accounting.
// Record ownership in the lock word itself: an exception between acquisition
// and a separate owner store must not mistake self-reentry for peer contention.
// No owner/VM call or callback runs while this short NX registry lock is held.
struct RegistryGuard {
  RegistryGuard() {
    const auto Self=reinterpret_cast<uintptr_t>(GetCurrentTEB());
    uintptr_t Empty=0;
    while (!Registry.compare_exchange_weak(Empty,Self,std::memory_order_acquire,std::memory_order_relaxed)) Empty=0;
  }
  ~RegistryGuard() { Registry.store(0,std::memory_order_release); }
};
struct TryRegistryGuard {
  bool Owned {};
  TryRegistryGuard() {
    const auto Self=reinterpret_cast<uintptr_t>(GetCurrentTEB());
    uintptr_t Seen=0;
    for (;;) {
      if (Registry.compare_exchange_weak(Seen,Self,std::memory_order_acquire,std::memory_order_relaxed)) { Owned=true; return; }
      if (Seen==Self) return; // Interrupted native copy: never wait on ourselves.
      Seen=0; // A peer's finite metadata access is contention, not lost ownership.
    }
  }
  ~TryRegistryGuard() { if (Owned) Registry.store(0,std::memory_order_release); }
};
// Reuse the source FEXUnixLib ARM64EC register-branch mechanism. An ordinary
// indirect ARM64EC call would invoke the FEX call checker before admission.
#ifdef ARCHITECTURE_arm64ec
static uint32_t __attribute__((naked)) CallBridge(const pear_fex_memory_request*, pear_fex_memory_response*) {
  asm(R"(
    adrp x16, %[Displace]
    ldr x16, [x16, #:lo12:%[Displace]]
    br x16
  )" :: [Displace] "S"(&BridgeDirect) : "memory");
}
#else
static uint32_t CallBridge(const pear_fex_memory_request* Q, pear_fex_memory_response* R) { return BridgeDirect(Q, R); }
#endif
static Binding* CurrentBinding() {
  const auto TEB = GetCurrentTEB();
  const auto ID = reinterpret_cast<uintptr_t>(TEB->ClientId.UniqueThread);
  if (!ID) return nullptr;
  // Context/Thread identities remain opaque here, including during destructor
  // cleanup. Their actual fields are checked only while Attach owns the object.
  for (auto& B : Bindings) if (B.TEB == TEB && B.NativeThread == ID && B.SourceKind != Binding::Kind::None) return &B;
  return nullptr;
}
// Diagnostic metadata only under existing source ownership; no owner call.
struct PearWriterRegistryGuard {
  bool Owned{};
  PearWriterRegistryGuard(){
    const auto self=reinterpret_cast<uintptr_t>(GetCurrentTEB());uintptr_t empty=0;
    Owned=self && Registry.compare_exchange_weak(empty,self,std::memory_order_acquire,std::memory_order_relaxed);
  }
  ~PearWriterRegistryGuard(){if(Owned)Registry.store(0,std::memory_order_release);}
};
static bool PearWriterActor(const void* thread,uint64_t life,PearWriterRecord& record) {
  PearWriterRegistryGuard lock;if(!lock.Owned)return false;
  const auto* b=CurrentBinding();
  if(!b || !thread || !life || b->SourceState!=thread || b->LifetimeSerial!=life ||
     !b->LifetimeHolds || b->LifetimeClosing || b->LifetimeDeleteSealed || b->Unresolved || b->Pending || b->Capturing || b->CleanupOnly ||
     b->SourceKind!=Binding::Kind::Thread ||
     (b->Active.Kind!=LeaseKind::None && b->Active.Kind!=LeaseKind::Pinned) || !b->Executor ||
     MutationExecutor.load(std::memory_order_acquire)!=b->Executor)return false;
  record.pid=OwnerPID;record.executor=b->Executor;record.thread=b->NativeThread;
  record.life=b->LifetimeSerial;record.source=reinterpret_cast<uintptr_t>(b->SourceState);
  record.turn=MutationSequence.load(std::memory_order_acquire);return true;
}
extern "C" uint64_t PearWriterBegin(PearWriterRecord* record,const void* thread,uint64_t life) {
  if(!record || !PearWriterActor(thread,life,*record)){PearWriterRing.Lose();return 0;}
  return PearWriterRing.Begin(*record);
}
extern "C" void PearWriterFinish(uint64_t id,bool stores,uint64_t status,uint64_t domain,uint64_t code,bool published,bool updated) {
  PearWriterRing.Finish(id,stores,status,domain,code,published,updated);
}
extern "C" bool PearWriterSnapshot(const void* thread,uint64_t life,PearWriterBatch* batch) {
  PearWriterRecord actor{};
  if(!batch || !PearWriterActor(thread,life,actor)){PearWriterRing.Lose();if(batch){*batch={};batch->lost=1;}return false;}
  return PearWriterRing.Snapshot(*batch);
}

static Binding CurrentSnapshot() {
  RegistryGuard Guard;
  auto* B = CurrentBinding();
  return B && !B->Pending && !B->Capturing && !B->Unresolved ? *B : Binding {};
}
static Result Refuse(uint32_t Status = PEAR_FEX_UNAVAILABLE) { return {Status, 0, 0}; }
static constexpr uint32_t CompiledSourceRole() {
#ifdef ARCHITECTURE_arm64ec
  return PEAR_FEX_ROLE_ARM64EC;
#else
  return PEAR_FEX_ROLE_NATIVE;
#endif
}
static Result NewAdmission() {
  if (Retirement::AdmissionOpen()) {
    RegistryGuard Guard;
    const auto* B=CurrentBinding(); const auto* C=B ? ContextRecord(B->SourceContext) : nullptr;
    return Refuse(B && (B->LifetimeClosing || B->CleanupOnly || !C || C->Closing || C->DeleteSealed || C->Retained) ? PEAR_FEX_UNAVAILABLE : PEAR_FEX_OK);
  }
  const auto First = Retirement::FirstFailureSnapshot();
  return First.Present && !First.Outcome ? First.Outcome : Refuse(PEAR_FEX_QUARANTINED);
}
static pear_fex_memory_request Request(uint32_t Opcode) {
  pear_fex_memory_request Q {};
  Q.version = PEAR_FEX_MEMORY_VERSION; Q.size = sizeof(Q); Q.opcode = Opcode;
  Q.owner_pid = Configured.load(std::memory_order_acquire) ? OwnerPID : 0;
  return Q;
}
static void Target(pear_fex_memory_request& Q, const Allocation& A, bool Epoch, bool State) {
  Q.allocation_id = A.Token.allocation_id; Q.generation = A.Token.generation;
  Q.extent_offset = A.Token.extent_offset; Q.extent_size = A.Token.extent_size;
  Q.allocation_class = A.Token.allocation_class; Q.ec_role = A.Token.ec_role;
  if (Epoch) Q.write_epoch = A.Token.write_epoch;
  if (State) Q.expected_state = A.Token.expected_state;
}
// Failure-only diagnostic; no owner operation or admission retry.
static void ObserveWriteFailure(const char* Phase, Result Outcome, bool Called, bool Validated) {
  const char* Enabled = std::getenv("PEAR_FEX_WRITE_OBSERVE");
  if (!Enabled || std::strcmp(Enabled, "1")) return;
  static std::atomic<unsigned> Count {};
  unsigned Sequence = Count.load(std::memory_order_relaxed);
  while (Sequence < 8 && !Count.compare_exchange_weak(Sequence, Sequence + 1, std::memory_order_relaxed)) {}
  if (Sequence >= 8) return;
  LogMan::Msg::EFmt("PEAR_WRITE phase={} seq={} status={} domain={} code={} called={} validated={}",
                   Phase, Sequence, Outcome.Status, Outcome.ErrorDomain, Outcome.ErrorCode,
                   unsigned(Called), unsigned(Validated));
}
struct InvocationFacts {
  bool BridgeCalled {};
  bool ValidatedRefusal {};
  // A candidate is only an identity for a checked cleanup attempt. It never
  // turns a malformed response into qualified registration or unregistration.
  uint64_t CleanupCandidate {};
};
static Result ResponseShapeFailure(uint32_t Opcode) {
  const auto Outcome = Refuse(PEAR_FEX_VERSION_MISMATCH);
  Retirement::PoisonSourceAdmission(Outcome);
  // A called mutating operation may have taken effect. Do not fabricate a
  // replacement allocation/token from malformed facts or silently forget it.
  // Retain this exact real Context/Thread and owner executor as unresolved.
  // REGISTER/UNREGISTER have their own captured-identity cleanup protocol;
  // QUERY changes no owner state and cannot establish a missing idle proof.
  if (Opcode != PEAR_FEX_EXECUTOR_REGISTER && Opcode != PEAR_FEX_EXECUTOR_UNREGISTER && Opcode != PEAR_FEX_QUERY) {
    RegistryGuard Guard;
    auto* B = CurrentBinding();
    if (B) {
      B->Unresolved = true;
      if (B->Active.Kind != LeaseKind::None) B->Active.Kind = LeaseKind::Unresolved;
      if (B->OriginalFailure) B->OriginalFailure = Outcome;
    }
  }
  return Outcome;
}
static Result Invoke(const pear_fex_memory_request& Q, pear_fex_memory_response& R, InvocationFacts* Facts = nullptr) {
  if (Facts) *Facts = {};
  R = {};
  if (!Configured.load(std::memory_order_acquire) || !BridgeDirect || !OwnerPID || Q.owner_pid != OwnerPID) return Refuse();
  const uint32_t Status = CallBridge(&Q, &R);
  if (Facts) {
    Facts->BridgeCalled = true;
    if (Q.opcode == PEAR_FEX_EXECUTOR_REGISTER && Status == PEAR_FEX_OK && R.status == PEAR_FEX_OK &&
        R.version == PEAR_FEX_MEMORY_VERSION && R.size == sizeof(R) && R.owner_pid == OwnerPID && R.executor_id)
      Facts->CleanupCandidate = R.executor_id;
  }
  if (R.version != PEAR_FEX_MEMORY_VERSION || R.size != sizeof(R) || R.status != Status ||
      Status > PEAR_FEX_QUARANTINED || R.reserved0 || R.flags > PEAR_FEX_UNREGISTERED ||
      R.native_error_domain > PEAR_FEX_ERROR_MACH || (!R.native_error_domain && R.native_error_code) ||
      R.capabilities & ~uint64_t(PEAR_FEX_CAPABILITIES_MASK) ||
      R.allocation_class > PEAR_FEX_CLASS_DISPATCHER || R.ec_role > PEAR_FEX_ROLE_NATIVE ||
      R.lifecycle_state > PEAR_FEX_RETIRED_NONE || R.effective_protection > PEAR_FEX_PROTECTION_RX)
    return ResponseShapeFailure(Q.opcode);
  if (Status != PEAR_FEX_OK) {
    if (R.flags || R.allocation_class || R.ec_role || R.owner_pid || R.allocation_id || R.generation ||
        R.write_epoch || R.executor_id || R.continuation_id || R.extent_offset || R.extent_size ||
        R.private_write_base || R.lifecycle_state || R.effective_protection || R.capabilities)
      return ResponseShapeFailure(Q.opcode);
    if (Facts) Facts->ValidatedRefusal = true;
    return {Status, R.native_error_domain, R.native_error_code};
  }
  if (R.owner_pid != OwnerPID || R.native_error_domain || R.native_error_code ||
      (Q.opcode != PEAR_FEX_BEGIN_WRITE && R.private_write_base) ||
      (Q.opcode != PEAR_FEX_QUERY && R.capabilities) ||
      (Q.executor_id && R.executor_id != Q.executor_id) ||
      (Q.allocation_id && (R.allocation_id != Q.allocation_id || R.generation != Q.generation ||
       R.extent_offset != Q.extent_offset || R.extent_size != Q.extent_size ||
       R.allocation_class != Q.allocation_class || R.ec_role != Q.ec_role)) ||
      (R.allocation_id && (!R.generation || !R.extent_size || !R.allocation_class || !R.ec_role ||
       (R.extent_offset & (PEAR_FEX_MEMORY_PAGE_BYTES-1)) ||
       (R.extent_size & (PEAR_FEX_MEMORY_PAGE_BYTES-1)) ||
       R.extent_size > std::numeric_limits<uint64_t>::max()-R.extent_offset)))
    return ResponseShapeFailure(Q.opcode);
  return {PEAR_FEX_OK, 0, 0};
}
static void Update(Allocation& A, const pear_fex_memory_response& R) {
  A.Token = Request(0);
  A.Token.allocation_id = R.allocation_id; A.Token.generation = R.generation;
  A.Token.write_epoch = R.write_epoch; A.Token.extent_offset = R.extent_offset;
  A.Token.extent_size = R.extent_size; A.Token.allocation_class = R.allocation_class;
  A.Token.ec_role = R.ec_role; A.Token.expected_state = R.lifecycle_state;
  A.Status = PEAR_FEX_OK; A.ErrorDomain = 0; A.ErrorCode = 0;
}
static bool TargetBinding(const Allocation& A, const Binding& B, bool DetachedCleanup = false) {
  const auto TEB = GetCurrentTEB();
  return Configured.load(std::memory_order_acquire) && B.TEB == TEB &&
         B.NativeThread && B.NativeThread == reinterpret_cast<uintptr_t>(TEB->ClientId.UniqueThread) &&
         B.SourceState && B.SourceContext && B.Executor && !B.Unresolved && B.Role == CompiledSourceRole() && B.Role == A.Token.ec_role &&
         ((!B.CleanupOnly && B.SourceKind == Binding::Kind::Thread) ||
          (B.SourceKind == Binding::Kind::Bootstrap &&
            ((!B.CleanupOnly && A.Token.allocation_class == PEAR_FEX_CLASS_DISPATCHER) ||
             (B.CleanupOnly && DetachedCleanup &&
               (A.Token.allocation_class == PEAR_FEX_CLASS_DISPATCHER || A.Token.allocation_class == PEAR_FEX_CLASS_SHARED))))) &&
         A.Status == PEAR_FEX_OK && !A.ErrorDomain && !A.ErrorCode &&
         A.Token.owner_pid == OwnerPID && A.Token.allocation_id && A.Token.generation;
}
static bool CurrentTarget(const Allocation& A, Binding& B, bool DetachedCleanup = false) {
  B = CurrentSnapshot();
  return TargetBinding(A, B, DetachedCleanup);
}
static bool SameBinding(const Binding& A, const Binding& B) {
  return A.TEB == B.TEB && A.NativeThread == B.NativeThread && A.SourceState == B.SourceState &&
         A.SourceContext == B.SourceContext && A.SourceKind == B.SourceKind &&
         A.Executor == B.Executor && A.Role == B.Role && A.Unresolved == B.Unresolved && A.LifetimeSerial == B.LifetimeSerial;
}
static bool SameAllocation(const Allocation& A, const Allocation& B) {
  return A.Base == B.Base && A.Status == B.Status && A.ErrorDomain == B.ErrorDomain &&
         A.ErrorCode == B.ErrorCode && std::memcmp(&A.Token, &B.Token, sizeof(A.Token)) == 0;
}
static size_t Usable(const Allocation& A) {
  if (A.Token.extent_size > std::numeric_limits<size_t>::max()) return 0;
  const auto Size = static_cast<size_t>(A.Token.extent_size);
  return A.Token.allocation_class == PEAR_FEX_CLASS_SHARED ?
         (Size >= PEAR_FEX_MEMORY_PAGE_BYTES ? Size-PEAR_FEX_MEMORY_PAGE_BYTES : 0) : Size;
}
// Capture a real current binding, invalidate the read proof and release the NX
// lock before crossing the native gate. Pending rejects same-thread reentry and
// never counts as a cooperative park acknowledgement in the Unix owner.
static Result BeginTransition(const Allocation* A, Binding& Snapshot, bool Entry, PendingTransition Transition) {
  RegistryGuard Guard;
  auto* B = CurrentBinding();
  if (!B || B->Pending || B->Capturing || B->Unresolved || !B->Executor || (A && !TargetBinding(*A, *B))) return Refuse();
  if (!A && B->LifetimeHolds) return Refuse();
  if (Entry && B->Active.Kind == LeaseKind::Active) return Refuse(PEAR_FEX_INVALID_REQUEST);
  Snapshot = *B;
  B->Active = {};
  B->Pending = true; B->Transition=Transition;
  return Refuse(PEAR_FEX_OK);
}
static Result FinishTransition(const Binding& Snapshot, Result Outcome, const Allocation* Entered = nullptr,
                               size_t EntryOffset = 0, uint64_t Continuation = 0, bool Unregistered = false) {
  RegistryGuard Guard;
  auto* B = CurrentBinding();
  if (!B || !B->Pending || !SameBinding(*B, Snapshot)) {
    const auto Lost = Outcome ? Refuse(PEAR_FEX_STALE_IDENTITY) : Outcome;
    Retirement::PoisonSourceAdmission(Lost);
    return Lost;
  }
  B->Pending = false; B->Transition=PendingTransition::Unknown;
  // A failed native transition never restores a stale positive read proof.
  B->Active = {};
  if (Outcome && Unregistered) {
    // Keep actual source identity/serial as a closing tombstone until actual
    // deletion or an exact checked bootstrap-to-thread transfer. No rebind ABA.
    B->Executor=0; B->Role=0; B->LifetimeClosing=true;
  }
  else if (Outcome && Entered) {
    B->Active = {*Entered, Snapshot.TEB, Snapshot.NativeThread, Snapshot.SourceState,
                 Snapshot.Executor, EntryOffset, Continuation, LeaseKind::Active};
  }
  return Outcome;
}
static Result Operation(const Allocation& A, uint32_t Opcode, uint64_t Continuation,
                        size_t Offset, uint64_t OverrideEpoch, pear_fex_memory_response& R,
                        const Binding* Captured = nullptr, bool ExistingHandoff = false, InvocationFacts* Facts = nullptr,
                        bool DetachedCleanup = false) {
  Binding B;
  if (Captured) {
    B = *Captured;
    if (!TargetBinding(A, B, DetachedCleanup)) return Refuse();
  } else if (!CurrentTarget(A, B, DetachedCleanup)) return Refuse();
  // CleanupOnly applies to existing as well as newly registered Bootstrap.
  // Even DISPATCHER PIN is refused: the private ledger route can only RETIRE.
  if (B.CleanupOnly && (!DetachedCleanup || Opcode != PEAR_FEX_RETIRE)) return Refuse();
  if (DetachedCleanup && Opcode != PEAR_FEX_RETIRE) return Refuse(PEAR_FEX_INVALID_REQUEST);
  if (ExistingHandoff && (Opcode != PEAR_FEX_EXECUTOR_HANDOFF || !Continuation || !OverrideEpoch))
    return Refuse(PEAR_FEX_INVALID_REQUEST);
  auto Q = Request(Opcode); Target(Q, A, Opcode != PEAR_FEX_QUERY, Opcode != PEAR_FEX_QUERY);
  Q.executor_id = B.Executor;
  if (Opcode == PEAR_FEX_CONTINUATION_UNPIN || ExistingHandoff) Q.write_epoch = OverrideEpoch;
  if (Opcode == PEAR_FEX_EXECUTOR_ENTRY || Opcode == PEAR_FEX_EXECUTOR_HANDOFF ||
      Opcode == PEAR_FEX_EXECUTOR_RESUME || Opcode == PEAR_FEX_CONTINUATION_UNPIN || Opcode == PEAR_FEX_QUERY) Q.continuation_id = Continuation;
  if (Opcode == PEAR_FEX_EXECUTOR_ENTRY || Opcode == PEAR_FEX_EXECUTOR_HANDOFF ||
      Opcode == PEAR_FEX_EXECUTOR_RESUME || Opcode == PEAR_FEX_CONTINUATION_PIN) {
    Q.operation_offset = Offset; Q.operation_size = ExistingHandoff ? 0 : 4;
  }
  const auto Result = Invoke(Q, R, Facts);
  if (!Result) return Result;
  // UNPIN validates the captured continuation epoch; its reply observes the
  // extent's current epoch, which may advance during a safely parked patch.
  if (Opcode != PEAR_FEX_QUERY && Opcode != PEAR_FEX_CONTINUATION_UNPIN &&
      Opcode != PEAR_FEX_EXECUTOR_HANDOFF && R.write_epoch != Q.write_epoch)
    return ResponseShapeFailure(Opcode);
  switch (Opcode) {
  case PEAR_FEX_QUERY:
    if (R.flags < PEAR_FEX_NATIVE_IDLE || R.flags > PEAR_FEX_PARKED || R.continuation_id != Continuation ||
        R.lifecycle_state < PEAR_FEX_RESERVED_NONE || R.lifecycle_state > PEAR_FEX_RETIRING ||
        (R.lifecycle_state == PEAR_FEX_RESERVED_NONE && R.effective_protection) ||
        (R.lifecycle_state == PEAR_FEX_WRITING_RW_NX &&
         (!R.write_epoch || R.effective_protection != PEAR_FEX_PROTECTION_RW_NX)) ||
        (R.lifecycle_state == PEAR_FEX_PUBLISHED_RX &&
         (!R.write_epoch || R.effective_protection != PEAR_FEX_PROTECTION_RX)) ||
        (R.lifecycle_state == PEAR_FEX_RETIRING && R.effective_protection == PEAR_FEX_PROTECTION_RW_NX))
      return ResponseShapeFailure(Opcode);
    break;
  case PEAR_FEX_EXECUTOR_ENTRY:
    if (R.flags != PEAR_FEX_MANAGED_ACTIVE || R.lifecycle_state != PEAR_FEX_PUBLISHED_RX ||
        R.effective_protection != PEAR_FEX_PROTECTION_RX || R.continuation_id != Continuation)
      return ResponseShapeFailure(Opcode);
    break;
  case PEAR_FEX_EXECUTOR_RESUME:
    if (R.flags != PEAR_FEX_MANAGED_ACTIVE || R.lifecycle_state != PEAR_FEX_PUBLISHED_RX ||
        R.effective_protection != PEAR_FEX_PROTECTION_RX || R.continuation_id)
      return ResponseShapeFailure(Opcode);
    break;
  case PEAR_FEX_EXECUTOR_EXIT:
    if (R.flags != PEAR_FEX_NATIVE_IDLE || R.lifecycle_state != PEAR_FEX_PUBLISHED_RX ||
        R.effective_protection || R.continuation_id) return ResponseShapeFailure(Opcode);
    break;
  case PEAR_FEX_CONTINUATION_PIN:
    if (!R.continuation_id || R.lifecycle_state != PEAR_FEX_PUBLISHED_RX || R.effective_protection ||
        (R.flags != PEAR_FEX_MANAGED_ACTIVE && R.flags != PEAR_FEX_NATIVE_PINNED))
      return ResponseShapeFailure(Opcode);
    break;
  case PEAR_FEX_EXECUTOR_HANDOFF:
    if (!R.continuation_id || (Continuation && R.continuation_id != Continuation) ||
        R.write_epoch < Q.write_epoch || R.flags != PEAR_FEX_NATIVE_PINNED || R.lifecycle_state != PEAR_FEX_PUBLISHED_RX || R.effective_protection)
      return ResponseShapeFailure(Opcode);
    break;
  case PEAR_FEX_CONTINUATION_UNPIN:
    if (R.continuation_id || R.effective_protection ||
        (R.flags != PEAR_FEX_NATIVE_IDLE && R.flags != PEAR_FEX_NATIVE_PINNED) ||
        (R.lifecycle_state != PEAR_FEX_PUBLISHED_RX && R.lifecycle_state != PEAR_FEX_RETIRING))
      return ResponseShapeFailure(Opcode);
    break;
  case PEAR_FEX_RETIRE:
    if (R.continuation_id || R.effective_protection || R.lifecycle_state != PEAR_FEX_RETIRED_NONE ||
        (R.flags != PEAR_FEX_NATIVE_IDLE && R.flags != PEAR_FEX_NATIVE_PINNED))
      return ResponseShapeFailure(Opcode);
    break;
  default: return Refuse(PEAR_FEX_INVALID_REQUEST);
  }
  return Result;
}
static bool NoTargetFacts(const pear_fex_memory_response& R) {
  return !R.allocation_id && !R.generation && !R.write_epoch && !R.continuation_id &&
    !R.extent_offset && !R.extent_size && !R.allocation_class && !R.ec_role &&
    !R.lifecycle_state && !R.effective_protection;
}
static Result CheckedUnregister(uint64_t Executor, InvocationFacts* Facts = nullptr) {
  if (!Executor) return Refuse(PEAR_FEX_INVALID_REQUEST);
  auto Q = Request(PEAR_FEX_EXECUTOR_UNREGISTER); Q.executor_id = Executor;
  pear_fex_memory_response R {};
  const auto Outcome = Invoke(Q, R, Facts);
  if (Outcome && (R.flags != PEAR_FEX_UNREGISTERED || !NoTargetFacts(R)))
    return ResponseShapeFailure(Q.opcode);
  return Outcome;
}
static Result ObserveRegisteredIdle(const Binding& B, InvocationFacts* Facts = nullptr) {
  auto Q = Request(PEAR_FEX_QUERY); Q.executor_id = B.Executor;
  pear_fex_memory_response R {};
  const auto Outcome = Invoke(Q, R, Facts);
  return Outcome && (R.flags != PEAR_FEX_NATIVE_IDLE || !NoTargetFacts(R)) ?
    ResponseShapeFailure(Q.opcode) : Outcome;
}
static bool ThreadFieldsMatch(const FEXCore::Context::Context* ActualContext,
                             const FEXCore::Core::InternalThreadState* Thread) {
  // This call is made while the real newly allocated source object is alive.
  // CurrentBinding and destructor cleanup never dereference this identity.
  return ActualContext && Thread && Thread->CTX == ActualContext && Thread->CurrentFrame &&
         Thread->CurrentFrame == &Thread->BaseFrameState && Thread->CurrentFrame->Thread == Thread;
}
static bool HasUnreleasedOwner(const Binding& B) {
  return B.Executor || B.Unresolved || B.Pending || B.Capturing || B.LifetimeHolds || (B.Active.Kind != LeaseKind::None);
}
static void RetainCleanup(Binding& B, Result Outcome, bool Called) {
  // Preserve the first actual cleanup failure. A later success/unperformed
  // refusal must not replace it; callers keep each immediate return too.
  if (!B.CleanupAttempted || B.CleanupOutcome) B.CleanupOutcome = Outcome;
  B.CleanupAttempted = B.CleanupAttempted || Called;
}
} // namespace

Result SourceLifecycle::Allocated(const FEXCore::Context::Context* Object) {
  if (!Object) return Refuse(PEAR_FEX_INVALID_REQUEST);
  RegistryGuard Guard;
  if (ContextRecord(Object) || NextLifetimeSerial == UINT64_MAX) return Refuse(PEAR_FEX_CAPACITY);
  for (auto& C:ContextLifetimes) if (!C.Object) {
    const auto TEB=GetCurrentTEB();
    const auto ID=reinterpret_cast<uintptr_t>(TEB->ClientId.UniqueThread);
    if (!ID) return Refuse(PEAR_FEX_STALE_IDENTITY);
    C={}; C.Object=Object; C.Serial=++NextLifetimeSerial;
    C.CreationTEB=TEB; C.CreationNativeThread=ID; return Refuse(PEAR_FEX_OK);
  }
  return Refuse(PEAR_FEX_CAPACITY);
}
SourceContextHold SourceLifecycle::HoldContext(const FEXCore::Context::Context* Object) {
  SourceContextHold Out;
  RegistryGuard Guard;
  auto* C=ContextRecord(Object);
  if (!C || C->Closing || C->Retained || C->DeleteSealed || C->Holds == UINT32_MAX) return Out;
  ++C->Holds; Out.Object=Object; Out.Serial=C->Serial; Out.Held=true; return Out;
}
SourceContextHold::SourceContextHold(SourceContextHold&& Other) noexcept {
  Object=Other.Object; Serial=Other.Serial; Held=std::exchange(Other.Held,false);
}
SourceContextHold::~SourceContextHold() { Release(); }
Result SourceContextHold::Release() {
  if (!Held) return Refuse(PEAR_FEX_OK);
  bool Good {};
  { RegistryGuard Guard; auto* C=ContextRecord(Object);
    Good=C && C->Serial == Serial && Serial && C->Holds && !C->DeleteSealed;
    if (Good) { --C->Holds; Held=false; }
    else if (C) { C->Closing=true; C->Retained=true; }
  }
  const auto Outcome=Refuse(Good ? PEAR_FEX_OK : PEAR_FEX_STALE_IDENTITY);
  if (!Good) Retirement::PoisonSourceAdmission(Outcome);
  return Outcome;
}
Result SourceLifecycle::CloseContext(const FEXCore::Context::Context* Object) {
  RegistryGuard Guard;
  auto* C=ContextRecord(Object); if (!C) return Refuse(PEAR_FEX_STALE_IDENTITY);
  const auto TEB=GetCurrentTEB();
  if (C->CreationTEB!=TEB || C->CreationNativeThread!=reinterpret_cast<uintptr_t>(TEB->ClientId.UniqueThread) ||
      C->DeleteSealed || C->DestroyedBacking || C->Retained) return Refuse(PEAR_FEX_STALE_IDENTITY);
  C->Closing=true;
  return Refuse(C->Holds ? PEAR_FEX_UNAVAILABLE : PEAR_FEX_OK);
}
Result SourceLifecycle::CloseThread(const FEXCore::Context::Context* Context, const FEXCore::Core::InternalThreadState* Thread) {
  RegistryGuard Guard;
  for (auto& B:Bindings) if (B.SourceKind == Binding::Kind::Thread && B.SourceState == Thread && B.SourceContext == Context) {
    const auto TEB=GetCurrentTEB();
    if (B.TEB!=TEB || B.NativeThread!=reinterpret_cast<uintptr_t>(TEB->ClientId.UniqueThread) || B.LifetimeDeleteSealed)
      return Refuse(PEAR_FEX_STALE_IDENTITY);
    B.LifetimeClosing=true;
    return Refuse(B.LifetimeHolds ? PEAR_FEX_UNAVAILABLE : PEAR_FEX_OK);
  }
  // Never registered/confirmed detached identities require the separate actual
  // construction owner proof. A missing table row does not itself grant delete.
  return Refuse(PEAR_FEX_STALE_IDENTITY);
}
Result SourceLifecycle::SealThreadDelete(const FEXCore::Core::InternalThreadState* Thread) {
  if (!Thread) return Refuse(PEAR_FEX_INVALID_REQUEST);
  RegistryGuard Guard;
  for (const auto& B:Bindings) {
    const bool Match=(B.SourceKind==Binding::Kind::Thread && B.SourceState==Thread) || B.AttachAttempt==Thread;
    if (Match) {
      const auto TEB=GetCurrentTEB();
      if (B.TEB!=TEB || B.NativeThread!=reinterpret_cast<uintptr_t>(TEB->ClientId.UniqueThread) ||
          B.LifetimeDeleteSealed || HasUnreleasedOwner(B) ||
          (B.SourceKind==Binding::Kind::Thread && !B.LifetimeClosing)) return Refuse(PEAR_FEX_STALE_IDENTITY);
    }
  }
  for (auto& B:Bindings) if ((B.SourceKind==Binding::Kind::Thread && B.SourceState==Thread) || B.AttachAttempt==Thread)
    B.LifetimeDeleteSealed=true;
  // A never-bound construction failure is owned by this private actual Core
  // constructor; missing metadata is not a public deletion permission.
  return Refuse(PEAR_FEX_OK);
}
Result SourceLifecycle::DeletedThread(const FEXCore::Core::InternalThreadState* Thread) {
  RegistryGuard Guard;
  for (const auto& B:Bindings) {
    const bool Match=(B.SourceKind == Binding::Kind::Thread && B.SourceState == Thread) || B.AttachAttempt == Thread;
    if (Match) {
      const auto TEB=GetCurrentTEB();
      if (B.TEB!=TEB || B.NativeThread!=reinterpret_cast<uintptr_t>(TEB->ClientId.UniqueThread) ||
          HasUnreleasedOwner(B) || !B.LifetimeDeleteSealed) return Refuse(PEAR_FEX_STALE_IDENTITY);
    }
  }
  // The caller is the private actual construction/deletion owner. Preserve
  // bootstrap Context identity if this was only its prospective AttachAttempt.
  for (auto& B:Bindings) {
    if (B.SourceKind == Binding::Kind::Thread && B.SourceState == Thread) B={};
    else if (B.AttachAttempt == Thread) { B.AttachAttempt=nullptr; B.LifetimeDeleteSealed=false; }
  }
  return Refuse(PEAR_FEX_OK);
}
Result SourceLifecycle::SealContextDelete(const FEXCore::Context::Context* Object) {
  RegistryGuard Guard;
  auto* C=ContextRecord(Object);
  const auto TEB=GetCurrentTEB();
  if (!C || !C->Closing || C->Holds || C->Retained || C->DeleteSealed || C->DestroyedBacking ||
      C->CreationTEB!=TEB || C->CreationNativeThread!=reinterpret_cast<uintptr_t>(TEB->ClientId.UniqueThread)) return Refuse();
  for (const auto& B:Bindings) if (B.SourceContext == Object && HasUnreleasedOwner(B)) return Refuse();
  for (const auto& B:Bindings) if (B.SourceContext == Object && B.SourceKind == Binding::Kind::Thread) return Refuse();
  C->DeleteSealed=true; return Refuse(PEAR_FEX_OK);
}
Result SourceLifecycle::BeginContextDestruction(const FEXCore::Context::Context* Object) {
  RegistryGuard Guard;
  auto* C=ContextRecord(Object); const auto TEB=GetCurrentTEB();
  if (!C || !C->Closing || !C->DeleteSealed || C->Holds || C->Retained || C->DestroyedBacking || C->DeletionStarted ||
      C->CreationTEB!=TEB || C->CreationNativeThread!=reinterpret_cast<uintptr_t>(TEB->ClientId.UniqueThread))
    return Refuse(PEAR_FEX_STALE_IDENTITY);
  for (const auto& B:Bindings) if (B.SourceContext==Object && (HasUnreleasedOwner(B) ||
      B.SourceKind==Binding::Kind::Thread || B.AttachAttempt)) return Refuse(PEAR_FEX_UNAVAILABLE);
  C->DeletionStarted=true; return Refuse(PEAR_FEX_OK);
}
Result SourceLifecycle::Deleted(const FEXCore::Context::Context* Object) {
  RegistryGuard Guard;
  auto* C=ContextRecord(Object);
  const auto TEB=GetCurrentTEB();
  if (!C || !C->DeleteSealed || !C->DeletionStarted || C->Holds || C->Retained || C->DestroyedBacking ||
      C->CreationTEB!=TEB || C->CreationNativeThread!=reinterpret_cast<uintptr_t>(TEB->ClientId.UniqueThread)) return Refuse(PEAR_FEX_STALE_IDENTITY);
  for (const auto& B:Bindings) if (B.SourceContext == Object && HasUnreleasedOwner(B)) return Refuse(PEAR_FEX_STALE_IDENTITY);
  for (auto& B:Bindings) if (B.SourceContext == Object) B={};
  *C={}; return Refuse(PEAR_FEX_OK);
}
void SourceLifecycle::Retain(const FEXCore::Context::Context* Object, Result Original) {
  { RegistryGuard Guard; if (auto* C=ContextRecord(Object)) { C->Closing=true; C->Retained=true; } }
  Retirement::PoisonSourceAdmission(Original ? Refuse(PEAR_FEX_UNAVAILABLE) : Original);
}
void SourceLifecycle::RetainDestroyed(const FEXCore::Context::Context* Object, Result Original) {
  { RegistryGuard Guard; if (auto* C=ContextRecord(Object)) {
      C->Closing=true; C->Retained=true; C->DestroyedBacking=true;
    } }
  // The allocation is retained, but its C++ backing has already been destroyed.
  // This is never a live-object lifetime or retry permission.
  Retirement::PoisonSourceAdmission(Original ? Refuse(PEAR_FEX_UNAVAILABLE) : Original);
}
SourceLifetime AcquireCurrentSourceLifetime(const FEXCore::Context::Context* ExpectedContext) {
  SourceLifetime Out;
  RegistryGuard Guard;
  auto* B=CurrentBinding();
  auto* C=B ? ContextRecord(B->SourceContext) : nullptr;
  if (!B || !C || (ExpectedContext && B->SourceContext != ExpectedContext) || B->SourceKind != Binding::Kind::Thread ||
      !B->Executor || !B->LifetimeSerial || B->LifetimeClosing || B->Pending || B->Capturing || B->Unresolved ||
      C->Closing || C->Retained || C->DeleteSealed || B->LifetimeHolds == UINT32_MAX || C->Holds == UINT32_MAX) return Out;
  ++B->LifetimeHolds; ++C->Holds;
  Out.BindingIndex=static_cast<uint32_t>(B-Bindings); Out.BindingSerial=B->LifetimeSerial;
  Out.ContextSerial=C->Serial; Out.Held=true; return Out;
}
namespace {
static bool LifetimeMatch(uint32_t I,uint64_t BindingSerial,uint64_t ContextSerial,bool RequireOpen) {
  if (I >= PEAR_FEX_MEMORY_MAX_EXECUTORS) return false;
  const auto& B=Bindings[I]; const auto* C=ContextRecord(B.SourceContext);
  return B.LifetimeSerial == BindingSerial && BindingSerial && B.LifetimeHolds && C &&
    C->Serial == ContextSerial && ContextSerial && C->Holds && !C->DeleteSealed && !C->Retained &&
    B.SourceKind == Binding::Kind::Thread && B.Executor && !B.Unresolved &&
    B.TEB == GetCurrentTEB() && B.NativeThread == reinterpret_cast<uintptr_t>(GetCurrentTEB()->ClientId.UniqueThread) &&
    (!RequireOpen || (!B.LifetimeClosing && !C->Closing));
}
}
SourceLifetime::SourceLifetime(SourceLifetime&& Other) noexcept {
  ContextSerial=Other.ContextSerial; BindingSerial=Other.BindingSerial; BindingIndex=Other.BindingIndex;
  Held=std::exchange(Other.Held,false);
}
SourceLifetime& SourceLifetime::operator=(SourceLifetime&& Other) noexcept {
  if (this != &Other) {
    const auto Released=Release();
    if (!Released) return *this; // Retain an uncertain existing hold; never overwrite its identity.
    ContextSerial=Other.ContextSerial; BindingSerial=Other.BindingSerial; BindingIndex=Other.BindingIndex;
    Held=std::exchange(Other.Held,false);
  }
  return *this;
}
SourceLifetime::~SourceLifetime() { Release(); }
void SourceLifetime::ObserveWakeCheckpoint(unsigned Phase, Result Outcome) const {
  if (Held) RecordWakeCheckpoint(BindingIndex,BindingSerial,Phase,Outcome);
}
Result SourceLifetime::Validate(bool RequireOpen) const {
  RegistryGuard Guard;
  return Refuse(Held && LifetimeMatch(BindingIndex,BindingSerial,ContextSerial,RequireOpen) ? PEAR_FEX_OK : PEAR_FEX_STALE_IDENTITY);
}
Result SourceLifetime::Release() {
  if (!Held) return Refuse(PEAR_FEX_OK);
  bool Valid {};
  { RegistryGuard Guard;
    // A closed/uncertain owner binding still needs its exact NX hold released,
    // so validate identity/counts without granting active or entry authority.
    if (BindingIndex < PEAR_FEX_MEMORY_MAX_EXECUTORS) {
      auto& B=Bindings[BindingIndex]; auto* C=ContextRecord(B.SourceContext);
      Valid=B.LifetimeSerial == BindingSerial && BindingSerial && B.LifetimeHolds &&
        C && C->Serial == ContextSerial && ContextSerial && C->Holds && !C->DeleteSealed &&
        B.TEB == GetCurrentTEB() && B.NativeThread == reinterpret_cast<uintptr_t>(GetCurrentTEB()->ClientId.UniqueThread);
      if (Valid) { --B.LifetimeHolds; --C->Holds; Held=false; }
      else if (C) { C->Closing=true; C->Retained=true; }
    }
  }
  const auto Outcome=Refuse(Valid ? PEAR_FEX_OK : PEAR_FEX_STALE_IDENTITY);
  if (!Valid) Retirement::PoisonSourceAdmission(Outcome);
  return Outcome;
}
const FEXCore::Context::Context* SourceLifetime::ActualContext() const {
  RegistryGuard Guard;
  return Held && LifetimeMatch(BindingIndex,BindingSerial,ContextSerial,false) ? Bindings[BindingIndex].SourceContext : nullptr;
}
FEXCore::Core::InternalThreadState* SourceLifetime::ActualThread() const {
  RegistryGuard Guard;
  return Held && LifetimeMatch(BindingIndex,BindingSerial,ContextSerial,false) ?
    const_cast<FEXCore::Core::InternalThreadState*>(static_cast<const FEXCore::Core::InternalThreadState*>(Bindings[BindingIndex].SourceState)) : nullptr;
}
uint64_t SourceLifetime::Executor() const {
  RegistryGuard Guard;
  return Held && LifetimeMatch(BindingIndex,BindingSerial,ContextSerial,false) ? Bindings[BindingIndex].Executor : 0;
}
SourceInvalidationHold SourceInvalidationHold::Acquire(const SourceLifetime& Actor,
    const FEXCore::Core::InternalThreadState* Target) {
  SourceInvalidationHold Out;
  if (!Actor || !Actor.Validate() || !Target) return Out;
  const auto* Context=Actor.ActualContext();
  // Existing batch admission belongs to this exact native executor. Never
  // acquire the source registry lock while checking the link registry.
  if (!Context || !Links::MutationAdmitted(Context)) return Out;
  RegistryGuard Guard;
  auto* Current=CurrentBinding(); auto* C=ContextRecord(Context);
  if (!Current || Current->SourceContext!=Context || Current->LifetimeSerial!=Actor.Identity() ||
      !Current->LifetimeHolds || !C || C->Closing || C->Retained || C->DeleteSealed || C->Holds==UINT32_MAX) return Out;
  for (auto& B:Bindings) if (B.SourceContext==Context && B.SourceKind==Binding::Kind::Thread && B.SourceState==Target) {
    if (!B.Executor || B.Unresolved || B.LifetimeClosing || B.LifetimeDeleteSealed || B.LifetimeHolds==UINT32_MAX) return Out;
    ++B.LifetimeHolds; ++C->Holds;
    Out.BindingIndex=static_cast<uint32_t>(&B-Bindings); Out.BindingSerial=B.LifetimeSerial;
    Out.ContextSerial=C->Serial; Out.Held=true; break;
  }
  return Out;
}
SourceInvalidationHold::SourceInvalidationHold(SourceInvalidationHold&& Other) noexcept {
  ContextSerial=Other.ContextSerial; BindingSerial=Other.BindingSerial; BindingIndex=Other.BindingIndex;
  Held=std::exchange(Other.Held,false);
}
SourceInvalidationHold::~SourceInvalidationHold() { Release(); }
Result SourceInvalidationHold::Release() {
  if (!Held) return Refuse(PEAR_FEX_OK);
  bool Valid {};
  { RegistryGuard Guard;
    if (BindingIndex<PEAR_FEX_MEMORY_MAX_EXECUTORS) {
      auto& B=Bindings[BindingIndex]; auto* C=ContextRecord(B.SourceContext);
      Valid=BindingSerial && B.LifetimeSerial==BindingSerial && B.LifetimeHolds && !B.LifetimeDeleteSealed &&
        C && ContextSerial && C->Serial==ContextSerial && C->Holds && !C->DeleteSealed;
      if (Valid) { --B.LifetimeHolds; --C->Holds; Held=false; }
      else if (C) { C->Closing=true; C->Retained=true; }
    }
  }
  const auto Outcome=Refuse(Valid ? PEAR_FEX_OK : PEAR_FEX_STALE_IDENTITY);
  if (!Valid) Retirement::PoisonSourceAdmission(Outcome);
  return Outcome;
}

Result WaitSourceEntryChange(const std::atomic<uint32_t>& Word, uint32_t Expected, uint32_t Milliseconds) {
  if (!Milliseconds || Milliseconds > 50) return Refuse(PEAR_FEX_INVALID_REQUEST);
  static_assert(sizeof(Word)==sizeof(uint32_t));
  LARGE_INTEGER Timeout; Timeout.QuadPart=-static_cast<int64_t>(Milliseconds)*10000;
  const auto Status=RtlWaitOnAddress(const_cast<std::atomic<uint32_t>*>(&Word),&Expected,sizeof(Expected),&Timeout);
  if (Status == STATUS_SUCCESS) return Refuse(PEAR_FEX_OK);
  if (Status == STATUS_TIMEOUT) return {PEAR_FEX_QUIESCENCE_TIMEOUT,PEAR_FEX_ERROR_NTSTATUS,static_cast<int32_t>(Status)};
  return {PEAR_FEX_NATIVE_FAILURE,PEAR_FEX_ERROR_NTSTATUS,static_cast<int32_t>(Status)};
}
void NotifySourceEntryChange(const std::atomic<uint32_t>& Word) {
  RtlWakeAddressAll(const_cast<std::atomic<uint32_t>*>(&Word));
}

// Failure-only metadata snapshot. Never wait for a registry holder.
struct MutationOwnerSnapshot {
  uint32_t State {4};
  uint64_t WineThread {}, Serial {};
  uint32_t Role {}, Lease {}, Holds {}, Flags {}, Transition {};
};
static MutationOwnerSnapshot CaptureMutationOwner(uint64_t Expected) {
  const auto Sequence=MutationSequence.load(std::memory_order_acquire);
  if (!Expected || MutationExecutor.load(std::memory_order_acquire)!=Expected) return {3};
  const auto Self=reinterpret_cast<uintptr_t>(GetCurrentTEB());
  uintptr_t Empty=0;
  if (!Registry.compare_exchange_strong(Empty,Self,std::memory_order_acquire,std::memory_order_relaxed)) return {2};
  MutationOwnerSnapshot Result {};
  unsigned Matches=0;
  for (const auto& B:Bindings) {
    if (B.Executor!=Expected || B.SourceKind==Binding::Kind::None) continue;
    ++Matches;
    Result={1,static_cast<uint64_t>(B.NativeThread),B.LifetimeSerial,B.Role,
            static_cast<uint32_t>(B.Active.Kind),B.LifetimeHolds,
            (B.Pending?1U:0U)|(B.Capturing?2U:0U)|(B.Unresolved?4U:0U)|
            (B.LifetimeClosing?8U:0U)|(B.LifetimeDeleteSealed?16U:0U)|(B.CleanupOnly?32U:0U),
            B.Pending?static_cast<uint32_t>(B.Transition):0U};
  }
  if (Matches!=1 || !Result.WineThread) Result={Matches>1?5U:4U};
  if (MutationExecutor.load(std::memory_order_acquire)!=Expected ||
      MutationSequence.load(std::memory_order_acquire)!=Sequence) Result={3};
  Registry.store(0,std::memory_order_release);
  return Result;
}
extern "C" bool PearMutationOwnerObservationEnabled();
extern "C" void PearMutationOwnerObservation(uint64_t, uint64_t, uint32_t, uint64_t, uint64_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);

extern "C" void PearMutationBoundObservation(uint64_t, uint64_t, uint64_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
extern "C" void PearMutationWaitObservation(uint64_t, uint64_t, uint32_t, uint32_t, uint64_t, uint64_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);

SourceMutationTurn::SourceMutationTurn(const SourceLifetime& Life, bool Writing)
  : SourceMutationTurn(Life, Writing, nullptr) {}
SourceMutationTurn::SourceMutationTurn(const SourceLifetime& Life, bool Writing, EntryDiagnostic* Diagnostic) {
  Outcome=Life.Validate();
  if (!Outcome) { EntryFailure(Diagnostic, 10, Outcome); return; }
  Executor=Life.Executor();
  // Local observation only; the original admission and finite loop are unchanged.
  uint64_t FirstOwner {}, LastOwner {};
  uint32_t Attempts {}, OwnerChanges {}, SequenceChanges {}, LastSequence {}, WaitsOK {}, WaitTimeouts {}, Polls {};
  for (unsigned Attempt=0;Attempt<1000;++Attempt) {
    const auto B=CurrentSnapshot();
    if (!Executor || B.Executor!=Executor || B.SourceContext!=Life.ActualContext() ||
        B.SourceState!=Life.ActualThread() ||
        (B.Active.Kind!=LeaseKind::None && B.Active.Kind!=LeaseKind::Pinned)) {
      Outcome=Refuse(PEAR_FEX_STALE_IDENTITY);
      EntryFailure(Diagnostic, 11, Outcome, static_cast<uint32_t>(B.Active.Kind), 1); return;
    }
    const auto Sequence=MutationSequence.load(std::memory_order_acquire);
    uint64_t Empty=0;
    if (MutationExecutor.compare_exchange_strong(Empty,Executor,std::memory_order_acquire,std::memory_order_relaxed)) {
      Owned=true;
      BeginWakeScan(Executor,Writing);
      if (Writing) {
        // Reuse FEX's existing block-boundary suspend check, not a new signal
        // handler or executable patch. Entry/resume holds the same source turn,
        // so no executor can become ACTIVE after this scan until publication.
        RegistryGuard Guard;
        for (auto& Peer:Bindings) {
          auto* Wake=CaptureWakePeer(Peer);
          if (Peer.Executor==Executor || Peer.SourceKind!=Binding::Kind::Thread ||
              Peer.Role!=PEAR_FEX_ROLE_ARM64EC || Peer.Active.Kind!=LeaseKind::Active ||
              Peer.LifetimeClosing || Peer.LifetimeDeleteSealed || Peer.Unresolved) continue;
          const auto* C=ContextRecord(Peer.SourceContext);
          if (Wake) Wake->Flags |= 64U | (C && !C->Closing && !C->DeleteSealed && !C->Retained ? 128U : 0U);
          if (!C || C->Closing || C->DeleteSealed || C->Retained) continue;
          // Registry ownership prevents lifetime sealing/deletion during this
          // bounded metadata-only access. No owner, VM or callback call occurs.
          auto* Thread=const_cast<FEXCore::Core::InternalThreadState*>(
            static_cast<const FEXCore::Core::InternalThreadState*>(Peer.SourceState));
          if (Wake) Wake->Flags |= 256U;
          if (Thread && Thread->CTX==Peer.SourceContext && Thread->CurrentFrame && Thread->CurrentFrame->Thread==Thread) {
            const auto Before=__atomic_fetch_or(&Thread->CurrentFrame->SuspendDoorbell,1U,__ATOMIC_RELEASE);
            if (Wake) { Wake->Flags |= 512U | 1024U; Wake->DoorbellBefore=Before; }
          }
        }
      }
      Outcome=Refuse(PEAR_FEX_OK); return;
    }
    // The linker synchronously invokes compilation on the same actual native
    // thread. The outer turn spans that nested work; no second release occurs.
    if (Empty==Executor) {
      if (WakeEnabled.load(std::memory_order_relaxed) && Writing && WakeSnapshot.Writer==Executor && WakeSnapshot.NestedWriting!=UINT32_MAX)
        ++WakeSnapshot.NestedWriting;
      Outcome=Refuse(PEAR_FEX_OK); return;
    }
    if (Diagnostic) {
      if (!Attempts) FirstOwner=Empty;
      else { OwnerChanges+=LastOwner!=Empty; SequenceChanges+=LastSequence!=Sequence; }
      LastOwner=Empty; LastSequence=Sequence; ++Attempts;
    }
    Waited=true;
    if (B.Active.Kind==LeaseKind::Pinned) {
      if (Diagnostic) ++Polls;
      Outcome=Poll(B.Active.Target,B.Active.EntryOffset,B.Active.Continuation,B.Active.Target.Token.write_epoch);
      if (!Outcome) { EntryFailure(Diagnostic, 12, Outcome); return; }
    }
    Outcome=WaitSourceEntryChange(MutationSequence,Sequence,5);
    if (Diagnostic) {
      if (Outcome) ++WaitsOK;
      else if (Outcome.Status==PEAR_FEX_QUIESCENCE_TIMEOUT) ++WaitTimeouts;
    }
    if (!Outcome && Outcome.Status!=PEAR_FEX_QUIESCENCE_TIMEOUT) { EntryFailure(Diagnostic, 13, Outcome); return; }
    Outcome=Life.Validate(); if (!Outcome) { EntryFailure(Diagnostic, 14, Outcome); return; }
    // One early observation per stable wait, before the unchanged final bound.
    // Snapshot is nonblocking; no owner call, new wait or retry is introduced.
    if (Diagnostic && Attempts==200 && !OwnerChanges && !SequenceChanges &&
        WaitTimeouts==200 && PearMutationOwnerObservationEnabled()) {
      const auto Owner=CaptureMutationOwner(LastOwner);
      PearMutationWaitObservation(Executor,LastOwner,LastSequence,Owner.State,Owner.WineThread,Owner.Serial,
                                 Owner.Role,Owner.Lease,Owner.Holds,Owner.Flags,Owner.Transition);
    }
  }
  Outcome=Refuse(PEAR_FEX_QUIESCENCE_TIMEOUT);
  EntryFailure(Diagnostic, 15, Outcome);
  if (Diagnostic) PearMutationBoundObservation(Executor,FirstOwner,LastOwner,Attempts,OwnerChanges,SequenceChanges,WaitsOK,WaitTimeouts,Polls);
  if (Diagnostic && PearMutationOwnerObservationEnabled()) {
    const auto Owner=CaptureMutationOwner(LastOwner);
    PearMutationOwnerObservation(Executor,LastOwner,Owner.State,Owner.WineThread,Owner.Serial,
                                 Owner.Role,Owner.Lease,Owner.Holds,Owner.Flags,Owner.Transition);
  }
}
SourceMutationTurn::SourceMutationTurn(SourceMutationTurn&& Other) noexcept
 : Outcome(Other.Outcome),Executor(Other.Executor),Owned(Other.Owned),Waited(Other.Waited) { Other.Owned=false; }
SourceMutationTurn::~SourceMutationTurn() { Release(); }
void SourceMutationTurn::Release() {
  if (!Owned) return;
  if (WakeEnabled.load(std::memory_order_relaxed)) WakeEpoch.store(0,std::memory_order_release);
  auto Expected=Executor;
  if (!MutationExecutor.compare_exchange_strong(Expected,0,std::memory_order_release,std::memory_order_relaxed)) {
    Retirement::PoisonSourceAdmission(Refuse(PEAR_FEX_STALE_IDENTITY)); return;
  }
  Owned=false;
  MutationSequence.fetch_add(1,std::memory_order_release);
  NotifySourceEntryChange(MutationSequence);
}

Result AssessMetadataBudget(const pear_fex_memory_metadata& M, uint64_t ExpectedPID,
                            uint64_t RequiredViews, uint64_t OtherBytes, uint64_t& Total) {
  Total=0;
  if (M.version!=PEAR_FEX_MEMORY_VERSION || M.size!=sizeof(M) || M.status!=PEAR_FEX_OK ||
      M.reserved0 || M.reserved1 || M.native_error_domain || M.native_error_code ||
      !ExpectedPID || M.owner_pid!=ExpectedPID || M.mapping_bytes!=UINT64_C(1588985856) ||
      M.baseline_mapping_bytes!=UINT64_C(1050935296) || M.page_bytes!=4096 ||
      M.leaf_coverage_bytes!=UINT64_C(4294967296) || M.leaf_backing_bytes!=1048576 ||
      !M.baseline_leaves || M.baseline_leaves>2 || M.additional_leaves>1 ||
      M.view_block_bytes!=1048576 || !M.view_record_bytes || M.view_record_bytes>M.view_block_bytes ||
      M.available_view_slots>PEAR_FEX_MEMORY_OBSERVATION_SLOTS || !M.fixed_native_bytes)
    return Refuse(PEAR_FEX_INVALID_REQUEST);
  if (!RequiredViews || RequiredViews>PEAR_FEX_MEMORY_OBSERVATION_SLOTS)
    return Refuse(PEAR_FEX_INVALID_REQUEST);
  // A new 1-MiB directory/view block alone exceeds the entire approved cap.
  if (M.additional_leaves || RequiredViews>M.available_view_slots ||
      M.fixed_native_bytes>PEAR_FEX_MEMORY_METADATA_BYTES || OtherBytes>PEAR_FEX_MEMORY_METADATA_BYTES)
    return Refuse(PEAR_FEX_CAPACITY);
  // Charge full fixed owner/adapter payload plus three boundary pages. Actual
  // linked placement must independently fit this conservative native bound.
  const uint64_t Native=((M.fixed_native_bytes+4095)/4096)*4096+3*4096;
  if (Native>PEAR_FEX_MEMORY_METADATA_BYTES || OtherBytes>PEAR_FEX_MEMORY_METADATA_BYTES-Native)
    return Refuse(PEAR_FEX_CAPACITY);
  Total=Native+OtherBytes;
  return Refuse(PEAR_FEX_OK);
}
Result ObserveMetadata(pear_fex_memory_metadata& Output) {
  Output={};
  if (!Configured.load(std::memory_order_acquire) || !BridgeDirect || !OwnerPID ||
      (CompiledSourceRole()!=PEAR_FEX_ROLE_NATIVE && CompiledSourceRole()!=PEAR_FEX_ROLE_ARM64EC)) return Refuse();
  auto Q=Request(PEAR_FEX_OBSERVE_METADATA);Q.ec_role=CompiledSourceRole();
  pear_fex_memory_response Raw {};
  const uint32_t Status=CallBridge(&Q,&Raw);
  pear_fex_memory_metadata M {};memcpy(&M,&Raw,sizeof(M));
  if (M.version!=PEAR_FEX_MEMORY_VERSION || M.size!=sizeof(M) || M.status!=Status ||
      Status>PEAR_FEX_QUARANTINED || M.reserved0 || M.reserved1 ||
      M.native_error_domain>PEAR_FEX_ERROR_MACH || (!M.native_error_domain && M.native_error_code))
    return Refuse(PEAR_FEX_VERSION_MISMATCH);
  if (Status!=PEAR_FEX_OK) {
    pear_fex_memory_metadata Empty {};
    Empty.version=M.version;Empty.size=M.size;Empty.status=M.status;
    Empty.native_error_domain=M.native_error_domain;Empty.native_error_code=M.native_error_code;
    if (memcmp(&Empty,&M,sizeof(M))) return Refuse(PEAR_FEX_VERSION_MISMATCH);
    return {Status,M.native_error_domain,M.native_error_code};
  }
  if (M.owner_pid!=OwnerPID || M.native_error_domain || M.native_error_code)
    return Refuse(PEAR_FEX_VERSION_MISMATCH);
  Output=M;return Refuse(PEAR_FEX_OK);
}
Result PrepareOwnerMetadata(pear_fex_memory_metadata& Output, Result& Cleanup, bool& CleanupAttempted) {
  Output={};Cleanup={};CleanupAttempted=false;
  if (!Configured.load(std::memory_order_acquire) || !BridgeDirect || !OwnerPID ||
      CompiledSourceRole()!=PEAR_FEX_ROLE_NATIVE) return Refuse();
  {
    RegistryGuard Guard;
    // The one-shot initializer calls this before constructing any source object.
    // Never borrow or impersonate a live Context/Thread executor.
    for (const auto& C:ContextLifetimes) if (C.Object) return Refuse();
    for (const auto& B:Bindings) if (B.TEB) return Refuse();
  }
  auto Q=Request(PEAR_FEX_EXECUTOR_REGISTER);Q.ec_role=PEAR_FEX_ROLE_NATIVE;
  pear_fex_memory_response R {};InvocationFacts Facts;
  auto Primary=Invoke(Q,R,&Facts);
  if (Primary && (!R.executor_id || R.flags!=PEAR_FEX_NATIVE_IDLE || !NoTargetFacts(R)))
    Primary=ResponseShapeFailure(Q.opcode);
  if (!Primary && Facts.BridgeCalled && !Facts.ValidatedRefusal)
    Retirement::PoisonSourceAdmission(Primary);
  pear_fex_memory_metadata Observed {};
  if (Primary) Primary=ObserveMetadata(Observed);
  // The validated success identity is retained even if observation fails. For
  // malformed registration, only the existing checked cleanup candidate may be
  // used; never fabricate an ID or replace the original error with cleanup.
  if (Facts.CleanupCandidate) {
    CleanupAttempted=true;Cleanup=CheckedUnregister(Facts.CleanupCandidate);
    if (!Cleanup) Retirement::PoisonSourceAdmission(Cleanup);
  }
  if (Primary && (!CleanupAttempted || !Cleanup)) return Primary;
  if (Primary) Output=Observed;
  return Primary;
}
Result Init(void* NtDll, uint64_t UnixOwnerPid) {
  if (!NtDll || !UnixOwnerPid) return Refuse(PEAR_FEX_INVALID_REQUEST);
  auto Resolved = reinterpret_cast<BridgeType>(GetProcAddress(static_cast<HMODULE>(NtDll), "__wine_pear_fex_memory"));
  if (!Resolved) return Refuse();
#ifdef ARCHITECTURE_arm64ec
  const auto ExportAddress = reinterpret_cast<uintptr_t>(Resolved);
  if (NtDllBase != reinterpret_cast<uintptr_t>(NtDll) || !NtDllRedirectionLUT ||
      ExportAddress < NtDllBase || ExportAddress-NtDllBase >= NtDllRedirectionLUTSize)
    return Refuse();
  const auto NativeRVA = NtDllRedirectionLUT[ExportAddress-NtDllBase];
  if (!NativeRVA || NtDllBase > std::numeric_limits<uintptr_t>::max()-NativeRVA) return Refuse();
  Resolved = reinterpret_cast<BridgeType>(NtDllBase+NativeRVA);
#endif
  const char* WakeOptIn=std::getenv("PEAR_FEX_WAKE_OBSERVE");
  const bool WakeOn=WakeOptIn && !std::strcmp(WakeOptIn,"1");
  RegistryGuard Guard;
  if (BridgeDirect) return BridgeDirect == Resolved && OwnerPID == UnixOwnerPid ? Refuse(PEAR_FEX_OK) : Refuse(PEAR_FEX_STALE_IDENTITY);
  WakeEnabled.store(WakeOn,std::memory_order_relaxed);
  BridgeDirect = Resolved; OwnerPID = UnixOwnerPid; Configured.store(true, std::memory_order_release);
  return Refuse(PEAR_FEX_OK);
}
namespace {
static Result BindActual(const FEXCore::Context::Context* Context, const void* SourceState, Binding::Kind Kind, PearAttach::Diagnostic* Diag=nullptr) {
  PearAttach::ClearIdentities(Diag);
  const auto Admission = NewAdmission();
  if (!Admission) return PearAttach::Capture(Diag,PearAttach::Branch::BindAdmission,Admission);
  if (!Context || !SourceState || !Configured.load(std::memory_order_acquire) || !BridgeDirect || !OwnerPID) return PearAttach::Capture(Diag,PearAttach::Branch::BindIdentity,Refuse());
  const auto TEB = GetCurrentTEB();
  const auto ID = reinterpret_cast<uintptr_t>(TEB->ClientId.UniqueThread);
  if (!ID) return PearAttach::Capture(Diag,PearAttach::Branch::BindIdentity,Refuse());
  RegistryGuard Guard;
  auto* Life = ContextRecord(Context);
  if (Diag && Life) { Diag->ContextSerial=Life->Serial; Diag->Flags|=PearAttach::ContextKnown; }
  if (!Life || Life->Closing || Life->DeleteSealed || Life->Retained) return PearAttach::Capture(Diag,PearAttach::Branch::BindIdentity,Refuse());
  Binding* Empty {};
  for (auto& B : Bindings) {
    if (B.TEB == TEB && B.NativeThread == ID) {
      if (Diag) { Diag->BindingSerial=B.LifetimeSerial; Diag->Flags|=PearAttach::BindingKnown; }
      if (B.Pending || B.Capturing || B.Unresolved || B.LifetimeClosing || B.SourceKind != Kind ||
          B.SourceContext != Context || B.SourceState != SourceState) return PearAttach::Capture(Diag,PearAttach::Branch::BindExistingIdentity,Refuse(PEAR_FEX_STALE_IDENTITY));
      return Refuse(PEAR_FEX_OK);
    }
    if (!B.TEB && !Empty) Empty = &B;
  }
  if (!Empty || NextLifetimeSerial == UINT64_MAX) {
    if (Diag) Diag->Flags|=PearAttach::CapacityKnown | (!Empty?PearAttach::NoEmptyBinding:0u) |
      (NextLifetimeSerial == UINT64_MAX?PearAttach::SerialExhausted:0u);
    if (Diag) PearBindings::Copy(Diag->Census,Bindings,NextLifetimeSerial);
    return PearAttach::Capture(Diag,PearAttach::Branch::BindCapacity,Refuse(PEAR_FEX_CAPACITY));
  }
  *Empty = {};
  Empty->TEB = TEB; Empty->NativeThread = ID; Empty->SourceState = SourceState;
  Empty->SourceContext = Context; Empty->SourceKind = Kind; Empty->LifetimeSerial = ++NextLifetimeSerial;
  if (Diag) { Diag->BindingSerial=Empty->LifetimeSerial; Diag->Flags|=PearAttach::BindingKnown; }
  return Refuse(PEAR_FEX_OK);
}
} // namespace
Result BindBootstrapContext(const FEXCore::Context::Context* Context) {
  return BindActual(Context, Context, Binding::Kind::Bootstrap);
}
Result BindSourceThread(const FEXCore::Core::InternalThreadState* Thread) {
  // Opaque identity first. Only actual Core construction can create the row.
  // Keep the real object protected while validating its original self fields.
  const FEXCore::Context::Context* Context {};
  { RegistryGuard Guard; const auto* B=CurrentBinding();
    if (!Thread || !B || B->SourceKind!=Binding::Kind::Thread || B->SourceState!=Thread ||
        B->LifetimeClosing || B->LifetimeDeleteSealed || B->Unresolved || B->Pending || B->Capturing)
      return Refuse(PEAR_FEX_STALE_IDENTITY);
    Context=B->SourceContext;
  }
  auto Life=AcquireCurrentSourceLifetime(Context);
  if (!Life || Life.ActualThread()!=Thread || !ThreadFieldsMatch(Context,Thread)) return Refuse(PEAR_FEX_STALE_IDENTITY);
  return Life.Validate();
}
namespace {
static Result RegisterActualExecutor(uint32_t SourceRole, bool CleanupOnly, PearAttach::Diagnostic* Diag=nullptr) {
  PearAttach::ClearIdentities(Diag);
  if (!CleanupOnly) {
    const auto Admission=NewAdmission(); if (!Admission) return PearAttach::Capture(Diag,PearAttach::Branch::RegisterAdmission,Admission);
  }
  Binding Snapshot;
  {
    RegistryGuard Guard;
    auto* B = CurrentBinding();
    auto* C=B ? ContextRecord(B->SourceContext) : nullptr;
    if (Diag && B) { Diag->BindingSerial=B->LifetimeSerial; Diag->Flags|=PearAttach::BindingKnown; }
    if (Diag && C) { Diag->ContextSerial=C->Serial; Diag->Flags|=PearAttach::ContextKnown; }
    if (!B || !C || C->DeleteSealed || C->Retained || C->DestroyedBacking || B->LifetimeClosing ||
        B->Executor || B->Pending || B->Capturing || B->Unresolved || SourceRole!=CompiledSourceRole() ||
        (CleanupOnly ? (!B->CleanupOnly || B->SourceKind!=Binding::Kind::Bootstrap || !C->Closing || C->Holds ||
          C->CreationTEB!=B->TEB || C->CreationNativeThread!=B->NativeThread) : (C->Closing || B->CleanupOnly))) return PearAttach::Capture(Diag,PearAttach::Branch::RegisterPrecheck,Refuse());
    B->Pending = true; B->Transition=PendingTransition::Unknown; Snapshot = *B;
  }
  auto Q = Request(PEAR_FEX_EXECUTOR_REGISTER); Q.ec_role = SourceRole;
  pear_fex_memory_response R {};
  InvocationFacts Facts;
  auto Outcome = Invoke(Q, R, &Facts);
  PearAttach::Intermediate(Diag,Outcome);
  if (Diag) {
    Diag->Flags|=PearAttach::BridgeFactsKnown | (Facts.BridgeCalled?PearAttach::BridgeCalled:0u) |
      (Facts.ValidatedRefusal?PearAttach::ValidatedRefusal:0u) | (Facts.CleanupCandidate?PearAttach::CleanupCandidateKnown:0u);
  }
  PearAttach::Capture(Diag,PearAttach::Branch::RegisterInvoke,Outcome);
  if (Outcome && (!R.executor_id || R.flags != PEAR_FEX_NATIVE_IDLE || !NoTargetFacts(R)))
    Outcome = PearAttach::Capture(Diag,PearAttach::Branch::RegisterResponseShape,ResponseShapeFailure(Q.opcode));
  const bool Uncertain = !Outcome && Facts.BridgeCalled && !Facts.ValidatedRefusal;
  Result Cleanup;
  InvocationFacts CleanupFacts;
  if (Uncertain) {
    Retirement::PoisonSourceAdmission(Outcome);
    // Only the observed called-success identity can be used for this cleanup.
    // A zero/malformed ID or failure response never invents an unregister call.
    if (Facts.CleanupCandidate) Cleanup = CheckedUnregister(Facts.CleanupCandidate, &CleanupFacts);
  }
  {
    RegistryGuard Guard;
    auto* B = CurrentBinding();
    if (!B || !SameBinding(*B, Snapshot) || !B->Pending) {
      const auto Lost = Outcome ? Refuse(PEAR_FEX_STALE_IDENTITY) : Outcome;
      Retirement::PoisonSourceAdmission(Lost);
      return PearAttach::Capture(Diag,PearAttach::Branch::RegisterFinishIdentity,Lost);
    }
    B->Pending = false; B->Transition=PendingTransition::Unknown;
    if (Outcome) {
      B->Executor = R.executor_id; B->Role = SourceRole;
      B->OriginalFailure = Refuse(PEAR_FEX_OK); B->CleanupOutcome = {}; B->CleanupAttempted = false;
    }
    else {
      B->OriginalFailure = Outcome; B->CleanupOutcome = Cleanup;
      B->CleanupAttempted = CleanupFacts.BridgeCalled;
      B->Unresolved = Uncertain && !Cleanup;
      B->Executor = B->Unresolved ? Facts.CleanupCandidate : 0;
      B->Role = B->Unresolved ? SourceRole : 0;
    }
  }
  return Outcome;
}
} // namespace
Result RegisterExecutor(uint32_t SourceRole) { return RegisterActualExecutor(SourceRole,false); }
Result SourceLifecycle::EnsureContextCleanupExecutor(const FEXCore::Context::Context* Context) {
  bool Registered {};
  {
    RegistryGuard Guard;
    auto* C=ContextRecord(Context); const auto TEB=GetCurrentTEB();
    const auto ID=reinterpret_cast<uintptr_t>(TEB->ClientId.UniqueThread);
    if (!C || !C->Closing || C->Holds || C->Retained || C->DeleteSealed || C->DestroyedBacking ||
        C->CreationTEB!=TEB || C->CreationNativeThread!=ID || !ID) return Refuse(PEAR_FEX_STALE_IDENTITY);
    for (const auto& Row:Bindings) if (Row.SourceContext==Context &&
        (Row.SourceKind==Binding::Kind::Thread || Row.AttachAttempt || Row.Unresolved || Row.Pending || Row.Capturing ||
         Row.LifetimeHolds || Row.Active.Kind!=LeaseKind::None)) return Refuse(PEAR_FEX_UNAVAILABLE);
    auto* B=CurrentBinding();
    if (B) {
      if (B->SourceContext!=Context || B->SourceKind!=Binding::Kind::Bootstrap || B->SourceState!=Context ||
          B->LifetimeClosing || B->LifetimeDeleteSealed) return Refuse(PEAR_FEX_STALE_IDENTITY);
      // Existing bootstrap is a genuine registered participant. A later
      // cleanup-only registration is actual, never a synthetic executor ID.
      Registered=!!B->Executor;
      B->CleanupOnly=true;
    } else {
      Binding* Empty {};
      for (auto& Row:Bindings) if (!Row.TEB && !Empty) Empty=&Row;
      if (!Empty || NextLifetimeSerial==UINT64_MAX) return Refuse(PEAR_FEX_CAPACITY);
      *Empty={}; Empty->TEB=TEB; Empty->NativeThread=ID;
      Empty->SourceContext=Context; Empty->SourceState=Context;
      Empty->SourceKind=Binding::Kind::Bootstrap; Empty->LifetimeSerial=++NextLifetimeSerial;
      Empty->CleanupOnly=true;
    }
  }
  // No registry lock crosses the actual source-bound REGISTER/query operation.
  const auto R=Registered ? Refuse(PEAR_FEX_OK) : RegisterActualExecutor(CompiledSourceRole(),true);
  if (!R) return R;
  return CheckBootstrapCleanup(Context);
}
uint64_t CurrentExecutor() { return CurrentSnapshot().Executor; }
uint32_t CurrentSourceRole() {
  const auto B = CurrentSnapshot();
  return B.SourceKind == Binding::Kind::Thread && B.Executor && B.Role == CompiledSourceRole() ? B.Role : 0;
}
Result UnregisterExecutor() {
  PearSlot::Scope PearObservation(PearSlot::Stage::Unregister);
  const auto PearOriginalBody=[&]() -> Result {
  Binding B;
  const auto Begun = BeginTransition(nullptr, B, false,PendingTransition::Unregister);
  if (!Begun) return Begun;
  InvocationFacts Facts;
  PearSlot::Scope PearBridge(PearSlot::Stage::BridgeUnregister,B.SourceContext,B.SourceState);
  const auto Outcome = CheckedUnregister(B.Executor, &Facts);
  PearBridge.Return(2,Outcome.Status,Outcome.ErrorDomain,Outcome.ErrorCode,bool(Outcome),false,false,Facts.BridgeCalled,Facts.ValidatedRefusal);
  if (!Outcome) {
    RegistryGuard Guard;
    auto* Actual = CurrentBinding();
    if (Actual && SameBinding(*Actual, B)) {
      if (Actual->OriginalFailure) Actual->OriginalFailure = Outcome;
      RetainCleanup(*Actual, Outcome, Facts.BridgeCalled);
      // Any failed cleanup retains the real object and closes new admission.
      // Even a positive-looking malformed reply is not unregister proof.
    }
    Retirement::PoisonSourceAdmission(Outcome);
  }
  const auto Finished = FinishTransition(B, Outcome, nullptr, 0, 0, true);
  if (!Outcome && Facts.BridgeCalled && !Facts.ValidatedRefusal) {
    RegistryGuard Guard;
    auto* Actual = CurrentBinding();
    if (Actual && SameBinding(*Actual, B)) Actual->Unresolved = true;
  }
  return Finished;
  };
  const auto PearReturned=PearOriginalBody();
  PearObservation.Return(2,PearReturned.Status,PearReturned.ErrorDomain,PearReturned.ErrorCode,bool(PearReturned));
  return PearReturned;
}
static Result AttachAllocatedThreadImpl(const FEXCore::Context::Context* Context,
                            FEXCore::Core::InternalThreadState* Thread, uint32_t SourceRole, PearAttach::Diagnostic* Diag) {
  if (!ThreadFieldsMatch(Context, Thread) || SourceRole != CompiledSourceRole())
    return PearAttach::Capture(Diag,PearAttach::Branch::InvalidArguments,Refuse(PEAR_FEX_INVALID_REQUEST));
  const auto Admission = NewAdmission();
  if (!Admission) return PearAttach::Capture(Diag,PearAttach::Branch::OuterAdmission,Admission);
  Binding Existing;
  bool SameThread {};
  {
    RegistryGuard Guard;
    auto* B = CurrentBinding();
    if (Diag) {
      const auto* C=ContextRecord(Context);
      if (C) { Diag->ContextSerial=C->Serial; Diag->Flags|=PearAttach::ContextKnown; }
      if (B) { Diag->BindingSerial=B->LifetimeSerial; Diag->Flags|=PearAttach::BindingKnown; }
    }
    if (B) {
      if (B->SourceContext != Context || B->Pending || B->Capturing || (B->Active.Kind != LeaseKind::None) || B->Unresolved)
        return B->Unresolved && !B->OriginalFailure ?
          PearAttach::Capture(Diag,PearAttach::Branch::ExistingPrior,B->OriginalFailure) :
          PearAttach::Capture(Diag,PearAttach::Branch::ExistingIdentity,Refuse(PEAR_FEX_STALE_IDENTITY));
      SameThread = B->SourceKind == Binding::Kind::Thread && B->SourceState == Thread;
      if (!SameThread && B->SourceKind != Binding::Kind::Bootstrap) return PearAttach::Capture(Diag,PearAttach::Branch::ExistingIdentity,Refuse(PEAR_FEX_STALE_IDENTITY));
      B->AttachAttempt = Thread;
      Existing = *B;
      if (SameThread && B->Executor) { B->Pending = true; B->Transition=PendingTransition::Unknown; }
      // A clean bootstrap or earlier confirmed registration refusal has no
      // owner executor. Erase only this exact live matching identity.
      if (!B->Executor && !HasUnreleasedOwner(*B) && B->SourceKind == Binding::Kind::Bootstrap) *B = {};
    }
  }
  if (SameThread && Existing.Executor) {
    if (Existing.Role != SourceRole) {
      const auto BadRole = Refuse(PEAR_FEX_STALE_IDENTITY);
      Retirement::PoisonSourceAdmission(BadRole);
      return PearAttach::Capture(Diag,PearAttach::Branch::SameThreadRole,FinishTransition(Existing, BadRole));
    }
    // Idempotence requires a new actual native-idle owner observation. The NX
    // lock was released before the call; no unregistered ID is reused.
    const auto Idle = ObserveRegisteredIdle(Existing);
    PearAttach::Intermediate(Diag,Idle);
    const auto Finished = FinishTransition(Existing, Idle);
    if (!Finished) {
      RegistryGuard Guard;
      auto* B = CurrentBinding();
      if (B && SameBinding(*B, Existing)) {
        B->OriginalFailure = Finished; B->CleanupOutcome = {}; B->CleanupAttempted = false;
      }
      Retirement::PoisonSourceAdmission(Finished);
    }
    return PearAttach::Capture(Diag,PearAttach::Branch::SameThreadIdleOrFinish,Finished);
  }
  if (Existing.Executor) {
    // Preserve the live bootstrap Context on any refusal/unknown cleanup.
    const auto Unregistered = UnregisterExecutor();
    if (!Unregistered) return PearAttach::Capture(Diag,PearAttach::Branch::BootstrapUnregister,Unregistered);
    // Clear only this exact known-unregistered bootstrap for the source-owned
    // transfer. A Thread tombstone is never discarded by Attach or CanRelease.
    RegistryGuard Guard;
    auto* B=CurrentBinding(); auto* C=ContextRecord(Context);
    if (!B || !C || C->Closing || C->DeleteSealed || C->Retained || B->SourceKind != Binding::Kind::Bootstrap ||
        B->SourceContext != Context || B->AttachAttempt != Thread || HasUnreleasedOwner(*B)) return PearAttach::Capture(Diag,PearAttach::Branch::BootstrapTransferIdentity,Refuse(PEAR_FEX_STALE_IDENTITY));
    *B={};
  }
  const auto Bound = BindActual(Context, Thread, Binding::Kind::Thread,Diag);
  if (!Bound) return Bound;
  return RegisterActualExecutor(SourceRole,false,Diag);
}
Result SourceLifecycle::AttachAllocatedThread(const FEXCore::Context::Context* Context,
    FEXCore::Core::InternalThreadState* Thread,uint32_t SourceRole) {
  return AttachAllocatedThreadImpl(Context,Thread,SourceRole,nullptr);
}
Result AttachAllocatedThreadObserved(const FEXCore::Context::Context* Context,
    FEXCore::Core::InternalThreadState* Thread,uint32_t SourceRole,PearAttach::Diagnostic* Diag) {
  if (Diag) *Diag={};
  return AttachAllocatedThreadImpl(Context,Thread,SourceRole,Diag);
}

namespace {
static bool CanRelease(const FEXCore::Core::InternalThreadState* Thread,
                       const FEXCore::Context::Context* Context) {
  if (!Thread && !Context) return false;
  RegistryGuard Guard;
  if (Context) {
    const auto* C=ContextRecord(Context);
    if (!C || C->Holds || C->Retained || C->DestroyedBacking) return false;
    for (const auto& B:Bindings) if (B.SourceContext==Context &&
        (B.SourceKind==Binding::Kind::Thread || B.AttachAttempt)) return false;
  }
  // First inspect the entire finite registry. Do not clear one safe record
  // before discovering a different retained registration for this object.
  for (const auto& B : Bindings) {
    const bool Matches = Thread ? (B.SourceKind == Binding::Kind::Thread && B.SourceState == Thread) || B.AttachAttempt == Thread : B.SourceContext == Context;
    if (Matches && HasUnreleasedOwner(B)) return false;
  }
  // Observation only. Tombstones survive checked owner unregister until
  // SourceLifecycle::DeletedThread/Deleted observes the actual deletion owner.
  return true;
}
static Result Diagnostic(const FEXCore::Core::InternalThreadState* Thread,
                         const FEXCore::Context::Context* Context, bool Cleanup) {
  if (!Thread && !Context) return Refuse(PEAR_FEX_INVALID_REQUEST);
  RegistryGuard Guard;
  for (const auto& B : Bindings) {
    const bool Matches = Thread ? (B.SourceKind == Binding::Kind::Thread && B.SourceState == Thread) || B.AttachAttempt == Thread : B.SourceContext == Context;
    if (Matches) return Cleanup ? B.CleanupOutcome : B.OriginalFailure;
  }
  return Refuse();
}
static bool CleanupAttempt(const FEXCore::Core::InternalThreadState* Thread,
                           const FEXCore::Context::Context* Context) {
  if (!Thread && !Context) return false;
  RegistryGuard Guard;
  for (const auto& B : Bindings) {
    const bool Matches = Thread ? (B.SourceKind == Binding::Kind::Thread && B.SourceState == Thread) || B.AttachAttempt == Thread : B.SourceContext == Context;
    if (Matches) return B.CleanupAttempted;
  }
  return false;
}
static Result CheckCleanup(const FEXCore::Context::Context* Context,
                           const FEXCore::Core::InternalThreadState* Thread) {
  if (!Context || (Thread && !ThreadFieldsMatch(Context, Thread))) return Refuse(PEAR_FEX_INVALID_REQUEST);
  Binding Snapshot;
  {
    RegistryGuard Guard;
    auto* B = CurrentBinding();
    const bool Match = B && B->SourceContext == Context &&
      (Thread ? B->SourceKind == Binding::Kind::Thread && B->SourceState == Thread :
                B->SourceKind == Binding::Kind::Bootstrap && B->SourceState == Context);
    if (!Match || !B->Executor || B->Role != CompiledSourceRole() ||
        B->Pending || B->Capturing || B->Unresolved || (B->Active.Kind != LeaseKind::None)) return Refuse();
    Snapshot = *B; B->Pending = true; B->Transition=PendingTransition::Unknown;
  }
  // Cleanup is allowed after poison, but never from an unknown identity. The
  // actual owner must report this exact executor native-idle on this thread.
  InvocationFacts Facts;
  const auto Idle = ObserveRegisteredIdle(Snapshot, &Facts);
  const auto Finished = FinishTransition(Snapshot, Idle);
  {
    RegistryGuard Guard;
    auto* B = CurrentBinding();
    if (B && SameBinding(*B, Snapshot)) RetainCleanup(*B, Finished, Facts.BridgeCalled);
  }
  if (!Finished) Retirement::PoisonSourceAdmission(Finished);
  return Finished;
}
} // namespace
bool SourceBindingCanRelease(const FEXCore::Core::InternalThreadState* Thread) { return CanRelease(Thread, nullptr); }
bool SourceContextCanRelease(const FEXCore::Context::Context* Context) { return CanRelease(nullptr, Context); }
Result CheckBootstrapCleanup(const FEXCore::Context::Context* Context) { return CheckCleanup(Context, nullptr); }
Result CheckThreadCleanup(const FEXCore::Core::InternalThreadState* Thread) {
  return Thread ? CheckCleanup(Thread->CTX, Thread) : Refuse(PEAR_FEX_INVALID_REQUEST);
}
Result GetOriginalAttachFailure(const FEXCore::Core::InternalThreadState* Thread) { return Diagnostic(Thread, nullptr, false); }
Result GetOriginalAttachFailure(const FEXCore::Context::Context* Context) { return Diagnostic(nullptr, Context, false); }
Result GetCleanupOutcome(const FEXCore::Core::InternalThreadState* Thread) { return Diagnostic(Thread, nullptr, true); }
Result GetCleanupOutcome(const FEXCore::Context::Context* Context) { return Diagnostic(nullptr, Context, true); }
bool CleanupWasAttempted(const FEXCore::Core::InternalThreadState* Thread) { return CleanupAttempt(Thread, nullptr); }
bool CleanupWasAttempted(const FEXCore::Context::Context* Context) { return CleanupAttempt(nullptr, Context); }
Result DrainPendingRetirements() { return Retirement::DrainAtNativeGate(); }
Allocation Reserve(size_t Size, uint32_t AllocationClass, uint32_t SourceRole) {
  Allocation A;
  const auto Admission = NewAdmission();
  if (!Admission) { A.Status = Admission.Status; A.ErrorDomain = Admission.ErrorDomain; A.ErrorCode = Admission.ErrorCode; return A; }
  const auto B = CurrentSnapshot();
  if (!B.Executor || B.Role != SourceRole || SourceRole != CompiledSourceRole() ||
      (B.SourceKind == Binding::Kind::Bootstrap && AllocationClass != PEAR_FEX_CLASS_DISPATCHER)) return A;
  auto Q = Request(PEAR_FEX_RESERVE);
  Q.executor_id = B.Executor; Q.extent_size = Size; Q.allocation_class = AllocationClass; Q.ec_role = SourceRole;
  pear_fex_memory_response R {};
  const auto Result = Invoke(Q, R);
  A.Status = Result.Status; A.ErrorDomain = Result.ErrorDomain; A.ErrorCode = Result.ErrorCode;
  if (!Result) return A;
  if (!R.allocation_id || !R.generation || R.write_epoch || R.continuation_id || R.extent_size != Size ||
      R.allocation_class != AllocationClass || R.ec_role != SourceRole || R.lifecycle_state != PEAR_FEX_RESERVED_NONE ||
      (R.flags != PEAR_FEX_NATIVE_IDLE && R.flags != PEAR_FEX_NATIVE_PINNED) ||
      R.effective_protection != PEAR_FEX_PROTECTION_NONE) {
    const auto Failed = ResponseShapeFailure(Q.opcode);
    A.Status = Failed.Status; A.ErrorDomain = Failed.ErrorDomain; A.ErrorCode = Failed.ErrorCode; return A;
  }
  Update(A, R);
  return A;
}
Result Query(Allocation& A) {
  pear_fex_memory_response R {};
  const auto Result = Operation(A, PEAR_FEX_QUERY, 0, 0, 0, R);
  if (Result) Update(A, R);
  // A mixed full extent remains explicitly unavailable. Keep the source token
  // for bounded publication/entry operations; no single-page fact is fabricated.
  return Result;
}
Result Enter(const Allocation& A, size_t EntryOffset, uint64_t Continuation) {
  return Enter(A, EntryOffset, Continuation, nullptr);
}
Result Enter(const Allocation& A, size_t EntryOffset, uint64_t Continuation, EntryDiagnostic* Diagnostic) {
  const auto Admission=NewAdmission(); if (!Admission) return EntryFailure(Diagnostic, 20, Admission);
  // Hold the actual source before accepting caller metadata. The seal blocks
  // new Prepared/batch work through queued owner entry and token acceptance.
  auto Life=AcquireCurrentSourceLifetime();
  if (!Life) return EntryFailure(Diagnostic, 21, Refuse(PEAR_FEX_STALE_IDENTITY));
  Links::SealedEntry Sealed;
  const auto SealedResult=Links::TrySealEntry(Life,Sealed); if (!SealedResult) return EntryFailure(Diagnostic, 22, SealedResult);
  const auto Limit=Usable(A);
  if (!A.Base || !A.Token.write_epoch || A.Token.expected_state!=PEAR_FEX_PUBLISHED_RX ||
      (EntryOffset&3) || EntryOffset>Limit || 4>Limit-EntryOffset) return EntryFailure(Diagnostic, 23, Refuse(PEAR_FEX_INVALID_REQUEST));
  const auto StillCurrent=Sealed.Validate(Life); if (!StillCurrent) return EntryFailure(Diagnostic, 24, StillCurrent);
  Binding B;
  const auto Begun=BeginTransition(&A,B,true,PendingTransition::Entry); if (!Begun) return EntryFailure(Diagnostic, 25, Begun);
  pear_fex_memory_response R {};
  const auto Outcome=Operation(A,PEAR_FEX_EXECUTOR_ENTRY,Continuation,EntryOffset,0,R,&B);
  EntryFailure(Diagnostic, 26, Outcome);
  const auto Finished=FinishTransition(B,Outcome,&A,EntryOffset,Continuation);
  EntryFailure(Diagnostic, 27, Finished);
  // Unknown owner/source results retain the original seal; no implicit grant
  // or rollback is fabricated. The original operation error remains primary.
  const auto Released=Sealed.Release();
  if (!Finished) return Finished;
  return EntryFailure(Diagnostic, 28, Released);
}
namespace {
static bool ManagedActiveMatches(const Allocation& A, const Binding& B) {
  if (B.Pending || B.SourceKind != Binding::Kind::Thread || !TargetBinding(A, B)) return false;
  const auto& Active = B.Active;
  const auto Limit = Usable(A);
  return Active.Kind == LeaseKind::Active && Active.TEB == B.TEB && Active.NativeThread == B.NativeThread &&
         Active.SourceState == B.SourceState && Active.Executor == B.Executor &&
         A.Base && A.Token.write_epoch && A.Token.expected_state == PEAR_FEX_PUBLISHED_RX &&
         !(Active.EntryOffset & 3) && Active.EntryOffset <= Limit && 4 <= Limit-Active.EntryOffset &&
         SameAllocation(Active.Target, A);
}
static bool SameActive(const ActiveLease& A, const ActiveLease& B) {
  return A.Kind == B.Kind && A.TEB == B.TEB && A.NativeThread == B.NativeThread &&
         A.SourceState == B.SourceState && A.Executor == B.Executor &&
         A.EntryOffset == B.EntryOffset && A.Continuation == B.Continuation &&
         SameAllocation(A.Target, B.Target);
}
static Result ObserveCommittedPage(uintptr_t Page, ULONG Protect, const void* AllocationBase) {
  MEMORY_BASIC_INFORMATION Info {};
  SIZE_T Returned {};
  const NTSTATUS Status = NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(Page),
                                               MemoryBasicInformation, &Info, sizeof(Info), &Returned);
  if (Status) return {PEAR_FEX_NATIVE_FAILURE, PEAR_FEX_ERROR_NTSTATUS, static_cast<int32_t>(Status)};
  const auto Begin = reinterpret_cast<uintptr_t>(Info.BaseAddress);
  if (Returned != sizeof(Info) || Info.State != MEM_COMMIT || Info.Protect != Protect ||
      Info.Type != MEM_PRIVATE || !Info.AllocationBase ||
      (AllocationBase && Info.AllocationBase != AllocationBase) ||
      (Begin & (PEAR_FEX_MEMORY_PAGE_BYTES-1)) || !Info.RegionSize ||
      (Info.RegionSize & (PEAR_FEX_MEMORY_PAGE_BYTES-1)) || Begin > Page ||
      Info.RegionSize > std::numeric_limits<uintptr_t>::max()-Begin ||
      Page-Begin > Info.RegionSize || PEAR_FEX_MEMORY_PAGE_BYTES > Info.RegionSize-(Page-Begin))
    return Refuse();
  return Refuse(PEAR_FEX_OK);
}
static Result ObservePages(uintptr_t Begin, size_t Size, ULONG Protect, const void* AllocationBase, uint32_t& Count) {
  const auto End = Begin+Size;
  auto Page = Begin & ~(uintptr_t(PEAR_FEX_MEMORY_PAGE_BYTES)-1);
  Count = 0;
  while (Page < End) {
    // The admitted read is at most one page of bytes, covering at most two
    // complete actual 4-KiB VM pages. No lookup/header arithmetic proves RX.
    if (Count == 2) return Refuse(PEAR_FEX_INVALID_REQUEST);
    const auto Observed = ObserveCommittedPage(Page, Protect, AllocationBase);
    if (!Observed) return Observed;
    ++Count;
    if (End-Page <= PEAR_FEX_MEMORY_PAGE_BYTES) break;
    Page += PEAR_FEX_MEMORY_PAGE_BYTES;
  }
  return Refuse(PEAR_FEX_OK);
}
}
bool HasManagedActive(const Allocation& A) {
  // A native exception that interrupted a short NX copy must refuse instead of
  // spinning on a lock held by this same thread. There is no owner/code query.
  TryRegistryGuard Guard;
  if (!Guard.Owned) return false;
  auto* B = CurrentBinding();
  return B && !B->Capturing && ManagedActiveMatches(A, *B);
}
namespace {
static ManagedReadResult CopyManagedRXImpl(const Allocation& Protection, const Allocation& A,
  const TokenState* TargetState, const void* ActualSourceThreadState, size_t Offset, std::span<uint8_t> Destination) {
  ManagedReadResult Read;
  const auto Limit = Usable(A);
  const auto Begin = reinterpret_cast<uintptr_t>(A.Base);
  const auto Dest = reinterpret_cast<uintptr_t>(Destination.data());
  const auto Size = Destination.size();
  const auto ProtectedBegin = reinterpret_cast<uintptr_t>(Protection.Base);
  if (TargetState && (!Protection || !A || A.ErrorDomain || A.ErrorCode || !ProtectedBegin ||
      Protection.Token.allocation_class != PEAR_FEX_CLASS_DISPATCHER ||
      A.Token.allocation_class != PEAR_FEX_CLASS_SHARED ||
      Protection.Token.ec_role != CompiledSourceRole() || A.Token.ec_role != Protection.Token.ec_role ||
      A.Token.owner_pid != Protection.Token.owner_pid || !A.Token.allocation_id || !A.Token.generation ||
      !A.Token.write_epoch || A.Token.expected_state != PEAR_FEX_PUBLISHED_RX)) {
    Read.Outcome = Refuse(); return Read;
  }
  if (!ActualSourceThreadState || !Begin || (Begin & (PEAR_FEX_MEMORY_PAGE_BYTES-1)) ||
      !A.Token.extent_size || (A.Token.extent_size & (PEAR_FEX_MEMORY_PAGE_BYTES-1)) ||
      !Dest || !Size || Size > MAX_MANAGED_READ_BYTES ||
      A.Token.extent_size > std::numeric_limits<uintptr_t>::max()-Begin ||
      Offset > Limit || Size > Limit-Offset || Begin > std::numeric_limits<uintptr_t>::max()-Offset ||
      Begin+Offset > std::numeric_limits<uintptr_t>::max()-Size || Dest > std::numeric_limits<uintptr_t>::max()-Size ||
      (Dest < Begin+A.Token.extent_size && Begin < Dest+Size) ||
      Protection.Token.extent_size > std::numeric_limits<uintptr_t>::max()-ProtectedBegin ||
      (Dest < ProtectedBegin+Protection.Token.extent_size && ProtectedBegin < Dest+Size)) {
    Read.Outcome = Refuse(PEAR_FEX_INVALID_REQUEST); return Read;
  }
  Binding Snapshot;
  {
    TryRegistryGuard Guard;
    if (!Guard.Owned) return Read;
    auto* B = CurrentBinding();
    if (!B || B->Capturing || B->SourceState != ActualSourceThreadState || !ManagedActiveMatches(Protection, *B)) return Read;
    B->Capturing = true; Snapshot = *B;
  }
  // No NX lock is held during an NT call or copy. Capturing prevents even a
  // same-thread native callback from clearing/replacing the original active
  // lease. All other managed readers remain governed by the original owner.
  uint32_t SourcePages {}, DestinationPages {};
  bool DestinationObserved {};
  auto Outcome = TargetState && !SameAllocation(TargetState->Snapshot(), A) ?
    Refuse(PEAR_FEX_STALE_IDENTITY) : Refuse(PEAR_FEX_OK);
  if (Outcome) Outcome = ObservePages(Dest, Size, PAGE_READWRITE, nullptr, DestinationPages);
  if (Outcome) {
    DestinationObserved = true;
    std::memset(Destination.data(), 0, Size);
    Outcome = ObservePages(Begin+Offset, Size, PAGE_EXECUTE_READ, A.Base, SourcePages);
  }
  if (Outcome) {
    TryRegistryGuard Guard;
    auto* B = Guard.Owned ? CurrentBinding() : nullptr;
    if (!B || !B->Capturing || !SameBinding(*B, Snapshot) || !SameActive(B->Active, Snapshot.Active) ||
        !ManagedActiveMatches(Protection, *B)) Outcome = Refuse(PEAR_FEX_STALE_IDENTITY);
  }
  if (Outcome && TargetState && !SameAllocation(TargetState->Snapshot(), A)) Outcome = Refuse(PEAR_FEX_STALE_IDENTITY);
  if (Outcome) std::memcpy(Destination.data(), reinterpret_cast<const void*>(Begin+Offset), Size);
  if (Outcome && TargetState && !SameAllocation(TargetState->Snapshot(), A)) Outcome = Refuse(PEAR_FEX_STALE_IDENTITY);
  {
    TryRegistryGuard Guard;
    auto* B = Guard.Owned ? CurrentBinding() : nullptr;
    if (B && B->Capturing && SameBinding(*B, Snapshot) && SameActive(B->Active, Snapshot.Active) &&
        ManagedActiveMatches(Protection, *B)) {
      // Successful copy and target validation are complete; exact ACTIVE/Capturing lease is still held.
      if(Outcome && TargetState)PearWriterReadCut(ActualSourceThreadState,Destination.data(),Offset,Size);
      B->Capturing = false;
    }
    else if (Outcome) Outcome = Refuse(PEAR_FEX_STALE_IDENTITY);
    // If the exact captured binding cannot be revalidated, leave its marker
    // closed. It cannot be used for entry/exit/handoff or resumed success.
  }
  if (!Outcome) {
    if (DestinationObserved) std::memset(Destination.data(), 0, Size);
    Read.Outcome = Outcome; return Read;
  }
  Read.Outcome = Outcome; Read.BytesCopied = Size;
  Read.SourcePagesObserved = SourcePages; Read.DestinationPagesObserved = DestinationPages;
  return Read;
}
} // namespace
ManagedReadResult CopyManagedRX(const Allocation& A, const void* ActualSourceThreadState,
                               size_t Offset, std::span<uint8_t> Destination) {
  return CopyManagedRXImpl(A, A, nullptr, ActualSourceThreadState, Offset, Destination);
}
ManagedReadResult CopyManagedRXUnderGlobalLease(const Allocation& ProtectionD, const RetainedManagedTarget& Target,
  const void* ActualSourceThreadState, size_t Offset, std::span<uint8_t> Destination) {
  if (!Target) return {};
  const auto Read=CopyManagedRXImpl(ProtectionD, Target.Captured, Target.SourceState, ActualSourceThreadState, Offset, Destination);
  // OFF exits without consulting the TEB; no static TLS access in this path.
  if (!Read || Read.BytesCopied!=52 || Destination.size()!=52 || !PearReadIdentityOwner.load(std::memory_order_acquire)) return Read;
  PearReadIdentityGuard lock;
  if (!lock.owned) { PearReadIdentityLost.store(true,std::memory_order_relaxed);return Read; }
  if (PearReadIdentityOwner.load(std::memory_order_relaxed)!=PearReadIdentitySelf()) return Read;
  if (PearReadIdentityLost.load(std::memory_order_relaxed)) return Read;
  auto& Scope=PearReadIdentityActive;
  if (Scope.thread==ActualSourceThreadState && Scope.dest==Destination.data() &&
      Scope.offset==Offset && Scope.bytes==Destination.size() && Read.BytesCopied==52) {
    auto& d=Scope.value;
    if (d.seen) d.seen=2;
    else {
      // Access through the existing friend reader, after its unchanged success checks.
      // No private-class layout, request ABI, additional target lookup or byte copy.
      d.seen=1;d.owner=reinterpret_cast<uintptr_t>(Target.Owner.get());
      d.state=reinterpret_cast<uintptr_t>(Target.SourceState);
      d.base=reinterpret_cast<uintptr_t>(Target.Captured.Base);
      d.owner_pid=Target.Captured.Token.owner_pid;
      d.allocation=Target.Captured.Token.allocation_id;d.generation=Target.Captured.Token.generation;
      d.extent=Target.Captured.Token.extent_offset;d.size=Target.Captured.Token.extent_size;
      d.epoch=Target.Captured.Token.write_epoch;d.expected=Target.Captured.Token.expected_state;
      d.aclass=Target.Captured.Token.allocation_class;d.role=Target.Captured.Token.ec_role;
      d.offset=Offset;d.bytes=Read.BytesCopied;
    }
  }
  return Read;
}

Result Exit(const Allocation& A) {
  Binding B;
  const auto Begun = BeginTransition(&A, B, false,PendingTransition::Exit);
  if (!Begun) return Begun;
  pear_fex_memory_response R {};
  const auto Outcome = Operation(A, PEAR_FEX_EXECUTOR_EXIT, 0, 0, 0, R, &B);
  return FinishTransition(B, Outcome);
}
Result Pin(const Allocation& A, size_t ResumeOffset, uint64_t& Continuation) {
  if (Continuation) return Refuse(PEAR_FEX_INVALID_REQUEST);
  pear_fex_memory_response R {};
  const auto Result = Operation(A, PEAR_FEX_CONTINUATION_PIN, 0, ResumeOffset, 0, R);
  if (Result) Continuation = R.continuation_id;
  return Result;
}
namespace {
static bool PinnedMatches(const Binding& B, const Allocation& Current, size_t Offset,
                          uint64_t Continuation, uint64_t OriginalEpoch, bool DispatcherOnly = false) {
  if (B.SourceKind != Binding::Kind::Thread || B.Active.Kind != LeaseKind::Pinned ||
      B.Active.TEB != B.TEB || B.Active.NativeThread != B.NativeThread ||
      B.Active.SourceState != B.SourceState || B.Active.Executor != B.Executor ||
      !Continuation || B.Active.Continuation != Continuation || B.Active.EntryOffset != Offset ||
      !OriginalEpoch || B.Active.Target.Token.write_epoch != OriginalEpoch ||
      (DispatcherOnly && Current.Token.allocation_class != PEAR_FEX_CLASS_DISPATCHER) ||
      Current.Token.expected_state != PEAR_FEX_PUBLISHED_RX || Current.Token.write_epoch < OriginalEpoch)
    return false;
  auto Original = B.Active.Target;
  Original.Token.write_epoch = Current.Token.write_epoch;
  return SameAllocation(Original, Current) && TargetBinding(Current, B);
}
static Result FinishPinTransition(const Binding& Before, Result Outcome, const InvocationFacts& Facts,
                                 const Allocation& A, size_t Offset, uint64_t Continuation,
                                 bool NewPin, bool Resumed, bool Released = false) {
  RegistryGuard Guard;
  auto* B = CurrentBinding();
  // ResponseShapeFailure may already have marked this same real binding
  // unresolved. Compare identities without erasing that uncertainty first.
  auto Observed = B ? *B : Binding {};
  Observed.Unresolved = Before.Unresolved;
  if (!B || !B->Pending || !SameBinding(Observed, Before)) {
    const auto Primary = Outcome ? Refuse(PEAR_FEX_STALE_IDENTITY) : Outcome;
    Retirement::PoisonSourceAdmission(Primary);
    return Primary;
  }
  const bool Unknown = B->Unresolved || (!Outcome && Facts.BridgeCalled &&
    (NewPin || !Facts.ValidatedRefusal));
  B->Pending = false; B->Transition=PendingTransition::Unknown; B->Active = {};
  if (Unknown) {
    // Retain only the real pre-call tuple, explicitly without ACTIVE or retry
    // authority. Initial HANDOFF uncertainty cannot adopt unreturned pin IDs.
    B->Active = Before.Active;
    if (B->Active.Kind != LeaseKind::None) B->Active.Kind = LeaseKind::Unresolved;
    B->Unresolved = true;
    const auto Primary = Outcome ? Refuse(PEAR_FEX_STALE_IDENTITY) : Outcome;
    if (B->OriginalFailure) B->OriginalFailure = Primary;
    Retirement::PoisonSourceAdmission(Primary);
    return Primary;
  }
  if (Outcome && !Released) {
    B->Active = {A, Before.TEB, Before.NativeThread, Before.SourceState, Before.Executor,
                 Offset, Resumed ? 0 : Continuation, Resumed ? LeaseKind::Active : LeaseKind::Pinned};
  } else if (!Outcome && !NewPin && (!Facts.BridgeCalled || Facts.ValidatedRefusal)) {
    // Only strict poll and ABI2 resume promise precommit pin retention. The
    // initial size-four HANDOFF may mint a pin before its park later fails.
    B->Active = Before.Active;
  } else if (!Outcome && Facts.BridgeCalled) {
    B->Unresolved = true;
    if (B->OriginalFailure) B->OriginalFailure = Outcome;
    Retirement::PoisonSourceAdmission(Outcome);
  }
  return Outcome;
}
}
Result Unpin(const Allocation& A, uint64_t Continuation, uint64_t PinEpoch) {
  if (!Continuation) return Refuse(PEAR_FEX_INVALID_REQUEST);
  const auto Original = CurrentSnapshot();
  // Retain the original leaf for other source PIN records. Only a captured
  // current HANDOFF tuple can change this source-side pinned-lease record.
  if (!PinnedMatches(Original, A, Original.Active.EntryOffset, Continuation, PinEpoch)) {
    pear_fex_memory_response R {};
    return Operation(A, PEAR_FEX_CONTINUATION_UNPIN, Continuation, 0, PinEpoch, R);
  }
  Binding B;
  const auto Begun = BeginTransition(&A, B, false,PendingTransition::Unpin);
  if (!Begun) return Begun;
  pear_fex_memory_response R {};
  InvocationFacts Facts;
  const auto Outcome = Operation(A, PEAR_FEX_CONTINUATION_UNPIN, Continuation, 0, PinEpoch, R, &B, false, &Facts);
  return FinishPinTransition(B, Outcome, Facts, A, 0, 0, false, false, true);
}
Result Handoff(const Allocation& A, size_t ResumeOffset, uint64_t& Continuation) {
  const auto Active = CurrentSnapshot();
  if (!ManagedActiveMatches(A, Active)) return Refuse(PEAR_FEX_STALE_IDENTITY);
  Binding B;
  const auto Begun = BeginTransition(&A, B, false,PendingTransition::Handoff);
  if (!Begun) return Begun;
  pear_fex_memory_response R {};
  InvocationFacts Facts;
  const auto Outcome = Operation(A, PEAR_FEX_EXECUTOR_HANDOFF, Continuation, ResumeOffset, 0, R, &B, false, &Facts);
  const auto Finished = FinishPinTransition(B, Outcome, Facts, A, ResumeOffset, R.continuation_id, true, false);
  if (Finished) Continuation = R.continuation_id;
  return Finished;
}
Result Poll(const Allocation& A, size_t ResumeOffset, uint64_t Continuation, uint64_t OriginalPinEpoch) {
  const auto Original = CurrentSnapshot();
  if (!PinnedMatches(Original, A, ResumeOffset, Continuation, OriginalPinEpoch))
    return Refuse(PEAR_FEX_STALE_IDENTITY);
  Binding B;
  const auto Begun = BeginTransition(&A, B, false,PendingTransition::Poll);
  if (!Begun) return Begun;
  pear_fex_memory_response R {};
  InvocationFacts Facts;
  const auto Outcome = Operation(A, PEAR_FEX_EXECUTOR_HANDOFF, Continuation, ResumeOffset,
                                 OriginalPinEpoch, R, &B, true, &Facts);
  // A positive poll keeps the original captured tuple; its reply may observe
  // a newer current extent epoch, not a replacement continuation epoch.
  return FinishPinTransition(B, Outcome, Facts, Original.Active.Target, ResumeOffset, Continuation, false, false);
}
Result Resume(const Allocation& CurrentD, size_t ResumeOffset, uint64_t Continuation, uint64_t OriginalPinEpoch) {
  const auto Source=CurrentSnapshot();
  auto Life=AcquireCurrentSourceLifetime(Source.SourceContext);
  if (!Life || !Links::EntryResumeAdmitted(Life)) return Refuse();
  const auto Admission = NewAdmission();
  if (!Admission) return Admission;
  const auto Original = CurrentSnapshot();
  if (!PinnedMatches(Original, CurrentD, ResumeOffset, Continuation, OriginalPinEpoch, true))
    return Refuse(PEAR_FEX_STALE_IDENTITY);
  // This is the atomic owner leaf. The actual Core call site must retain its
  // sealed entry and actual object lifetimes; neither is created by this call.
  Binding B;
  const auto Begun = BeginTransition(&CurrentD, B, false,PendingTransition::Resume);
  if (!Begun) return Begun;
  pear_fex_memory_response R {};
  InvocationFacts Facts;
  const auto Outcome = Operation(CurrentD, PEAR_FEX_EXECUTOR_RESUME, Continuation, ResumeOffset, 0, R, &B, false, &Facts);
  return FinishPinTransition(B, Outcome, Facts, CurrentD, ResumeOffset, 0, false, true);
}
Result SourceLifecycle::RetireDetachedAtCleanupGate(Allocation& A) {
  // Private friend entry is called only with the exact retained ledger Take
  // target. The owner rechecks actual identity/generation/role/epoch before
  // observed retirement; no shadow metadata or fabricated NONE is accepted.
  pear_fex_memory_response R {};
  const auto Result=Operation(A,PEAR_FEX_RETIRE,0,0,0,R,nullptr,false,nullptr,true);
  if (Result) { Update(A,R); A.Base=nullptr; A.Status=PEAR_FEX_STALE_IDENTITY; }
  return Result;
}
Result Retire(Allocation& A) {
  pear_fex_memory_response R {};
  const auto Result = Operation(A, PEAR_FEX_RETIRE, 0, 0, 0, R);
  if (Result) { Update(A, R); A.Base = nullptr; A.Status = PEAR_FEX_STALE_IDENTITY; }
  return Result;
}
WriteGuard::WriteGuard(Allocation& A, size_t Offset, size_t Size, uint64_t Continuation)
  : Owner(A), WindowSize(Size) {
  Outcome = NewAdmission();
  if (!Outcome) { ObserveWriteFailure("admission", Outcome, false, false); return; }
  Binding B;
  const auto Limit = Usable(A);
  if (!Size || Offset > Limit || Size > Limit-Offset || !CurrentTarget(A, B)) { Outcome = Refuse(); return; }
  Request = PearFEXMemory::Request(PEAR_FEX_BEGIN_WRITE); Target(Request, A, true, true);
  Request.executor_id = B.Executor; Request.continuation_id = Continuation;
  Request.operation_offset = Offset; Request.operation_size = Size;
  pear_fex_memory_response R {};
  InvocationFacts Facts;
  Outcome = Invoke(Request, R, &Facts);
  if (!Outcome) { ObserveWriteFailure("invoke", Outcome, Facts.BridgeCalled, Facts.ValidatedRefusal); ObserveWakeFailure(Request.executor_id); return; }
  if (!R.private_write_base || R.private_write_base < Offset ||
      R.private_write_base > std::numeric_limits<uintptr_t>::max() ||
      R.private_write_base > std::numeric_limits<uintptr_t>::max()-Size ||
      R.lifecycle_state != PEAR_FEX_WRITING_RW_NX || R.effective_protection != PEAR_FEX_PROTECTION_RW_NX ||
      (R.flags != PEAR_FEX_NATIVE_IDLE && R.flags != PEAR_FEX_NATIVE_PINNED) ||
      !R.write_epoch || R.write_epoch <= Request.write_epoch || R.continuation_id != Continuation ||
      ((R.private_write_base-Offset) & (PEAR_FEX_MEMORY_PAGE_BYTES-1)) ||
      (A.Base && reinterpret_cast<uintptr_t>(A.Base) != R.private_write_base-Offset)) {
    Outcome = ResponseShapeFailure(Request.opcode); return;
  }
  Open = true; WriteBase = reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(R.private_write_base));
  A.Base = WriteBase-Offset; Update(A, R);
  Request.write_epoch = R.write_epoch; Request.expected_state = R.lifecycle_state;
  Request.operation_offset = Request.operation_size = 0;
}
WriteGuard::~WriteGuard() { if (Open) Abort(); }
bool WriteGuard::Matches(size_t RelativeOffset, std::span<const uint8_t> Expected) const {
  return Open && RelativeOffset <= WindowSize && Expected.size() <= WindowSize-RelativeOffset &&
         (Expected.empty() || std::memcmp(WriteBase+RelativeOffset, Expected.data(), Expected.size()) == 0);
}
Result WriteGuard::Publish() {
  if (!Open) return Outcome;
  const auto Admission = NewAdmission();
  if (!Admission) { Outcome = Admission; return Outcome; }
  Request.opcode = PEAR_FEX_PUBLISH;
  pear_fex_memory_response R {};
  const auto Result = Invoke(Request, R);
  if (!Result) { Outcome = Result; return Result; }
  if (R.lifecycle_state != PEAR_FEX_PUBLISHED_RX || R.effective_protection != PEAR_FEX_PROTECTION_RX ||
      (R.flags != PEAR_FEX_NATIVE_IDLE && R.flags != PEAR_FEX_NATIVE_PINNED) ||
      R.write_epoch != Request.write_epoch || R.continuation_id != Request.continuation_id) {
    Outcome = ResponseShapeFailure(Request.opcode); return Outcome;
  }
  Update(Owner, R); Open = false; WriteBase = nullptr; Outcome = Result;
  return Result;
}
Result WriteGuard::Abort() {
  if (!Open) return Outcome;
  Request.opcode = PEAR_FEX_ABORT_WRITE;
  pear_fex_memory_response R {};
  const bool AbortObserved=PearAbortEnabled();
  InvocationFacts AbortFacts;
  auto Result = Invoke(Request, R, AbortObserved ? &AbortFacts : nullptr);
  if (Result && (R.lifecycle_state != PEAR_FEX_RESERVED_NONE || R.effective_protection ||
      R.write_epoch != Request.write_epoch || R.continuation_id != Request.continuation_id ||
      (R.flags != PEAR_FEX_NATIVE_IDLE && R.flags != PEAR_FEX_NATIVE_PINNED)))
    Result = ResponseShapeFailure(Request.opcode);
  Open = false; WriteBase = nullptr;
  if (Result) { Update(Owner, R); Owner.Base = nullptr; }
  else { Owner.Status = Result.Status; Owner.ErrorDomain = Result.ErrorDomain; Owner.ErrorCode = Result.ErrorCode; Owner.Base = nullptr; }
  if (Outcome) Outcome = Result;
  if (AbortObserved && !Result) {
    PearAbortRecord d {};
    d.guard=reinterpret_cast<uintptr_t>(this);
    d.pid = Request.owner_pid;
    d.executor = Request.executor_id;
    d.allocation = Request.allocation_id;
    d.generation = Request.generation;
    d.extent = Request.extent_offset;
    d.size = Request.extent_size;
    d.epoch = Request.write_epoch;
    d.expected = Request.expected_state;
    d.aclass = Request.allocation_class;
    d.role = Request.ec_role;
    d.continuation = Request.continuation_id;
    d.bridge=AbortFacts.BridgeCalled; d.validated=AbortFacts.ValidatedRefusal;
    d.status=Result.Status; d.domain=Result.ErrorDomain; d.code=Result.ErrorCode;
    PearAbortEmit(2,&d);
  }
  return Result;
}
} // namespace FEXCore::Utils::PearFEXMemory

#include "PearSlotLifetimeMemory.inc"
