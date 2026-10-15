// SPDX-License-Identifier: MIT
// Original Pear source-side owner hooks; the Wine header is authoritative.
#pragma once
#include <wine/pear_fex_memory.h>
#include <cstddef>
#include <cstdint>
#include <span>
#include <atomic>
#include <cstring>
#include <memory>
#include <utility>

namespace FEXCore::CPU { class CPUBackend; struct CodeBuffer; }
namespace FEXCore::Context { class Context; class ContextImpl; struct PearContextDeleter; }
namespace FEXCore::Core { struct InternalThreadState; }

namespace FEXCore::Utils::PearFEXMemory {
struct Allocation {
  pear_fex_memory_request Token {};
  uint8_t* Base {};
  uint32_t Status {PEAR_FEX_UNAVAILABLE};
  uint32_t ErrorDomain {};
  int32_t ErrorCode {};
  explicit operator bool() const { return Status == PEAR_FEX_OK; }
};
// This bounded NX holder protects source token copies. Its lock is never
// retained across an owner call, quiescence wait, source callback or code read.
// A writer snapshots, releases this lock, performs the checked transaction,
// then compares/replaces before releasing a new lookup pointer. A reader that
// races the final publication sees a stale epoch and must refuse/retry at the
// source native gate; it never reads a concurrently modified wire struct.
class TokenState {
public:
  TokenState() = default;
  explicit TokenState(const Allocation& Initial) : Value(Initial) {}
  TokenState(const TokenState&) = delete;
  TokenState& operator=(const TokenState&) = delete;
  Allocation Snapshot() const {
    Lock(); auto Copy = Value; Unlock(); return Copy;
  }
  bool CompareUpdate(const Allocation& Expected, const Allocation& Next) {
    Lock();
    const bool Matches = Value.Base == Expected.Base && Value.Status == Expected.Status &&
      Value.ErrorDomain == Expected.ErrorDomain && Value.ErrorCode == Expected.ErrorCode &&
      std::memcmp(&Value.Token, &Expected.Token, sizeof(Value.Token)) == 0;
    if (Matches) Value = Next;
    Unlock(); return Matches;
  }
private:
  void Lock() const { while (Mutex.test_and_set(std::memory_order_acquire)) {} }
  void Unlock() const { Mutex.clear(std::memory_order_release); }
  Allocation Value {};
  mutable std::atomic_flag Mutex = ATOMIC_FLAG_INIT;
};
struct Result {
  uint32_t Status {PEAR_FEX_UNAVAILABLE};
  uint32_t ErrorDomain {};
  int32_t ErrorCode {};
  explicit operator bool() const { return Status == PEAR_FEX_OK; }
};
// Read-only owner snapshot, separate from allocation/publication responses.
Result ObserveMetadata(pear_fex_memory_metadata& Output);
// One finite pre-engine preparation. Register an idle native executor, observe
// read-only metadata and unregister it before returning. This creates no source
// lifetime and grants no executable extent. Preserve primary and cleanup errors.
Result PrepareOwnerMetadata(pear_fex_memory_metadata& Output, Result& Cleanup, bool& CleanupAttempted);

// OtherBytes is the source-selected PE storage and simultaneous transient bound.
// It never grants permission and is not a caller-selectable initialization gate.
Result AssessMetadataBudget(const pear_fex_memory_metadata& Facts, uint64_t ExpectedPID,
                            uint64_t RequiredViews, uint64_t OtherBytes, uint64_t& Total);
// Source ownership only: this move-only handle protects the exact actual
// Context/Thread while no NX registry lock is held across owner calls. It is
// minted only from the current genuine TEB/binding, never from caller facts.
class SourceLifetime {
public:
  SourceLifetime() = default;
  SourceLifetime(const SourceLifetime&) = delete;
  SourceLifetime& operator=(const SourceLifetime&) = delete;
  SourceLifetime(SourceLifetime&&) noexcept;
  SourceLifetime& operator=(SourceLifetime&&) noexcept;
  ~SourceLifetime();
  explicit operator bool() const { return Held; }
  Result Validate(bool RequireOpen = true) const;
  Result Release();
  const FEXCore::Context::Context* ActualContext() const;
  FEXCore::Core::InternalThreadState* ActualThread() const;
  uint64_t Executor() const;
  uint64_t Identity() const { return BindingSerial; }
private:
  friend SourceLifetime AcquireCurrentSourceLifetime(const FEXCore::Context::Context*);
  uint64_t ContextSerial {}, BindingSerial {};
  uint32_t BindingIndex {};
  bool Held {};
};
static_assert(sizeof(SourceLifetime) <= 32, "Bounded actual-source lifetime handle");
// A null expected identity selects only the opaque current actual binding.
// This does not admit an identity from a caller Frame or dereference it.
SourceLifetime AcquireCurrentSourceLifetime(const FEXCore::Context::Context* ExpectedContext = nullptr);
// Source mutations serialize before taking source locks or capturing write
// epochs. Waiting pinned executors cooperate through the existing owner poll.
// Callers retain their actual SourceLifetime until this turn is released.
class SourceMutationTurn {
public:
  explicit SourceMutationTurn(const SourceLifetime&, bool Writing=true);
  SourceMutationTurn(const SourceMutationTurn&)=delete;
  SourceMutationTurn& operator=(const SourceMutationTurn&)=delete;
  SourceMutationTurn(SourceMutationTurn&&) noexcept;
  ~SourceMutationTurn();
  explicit operator bool() const { return !!Outcome; }
  Result Status() const { return Outcome; }
  bool Contended() const { return Waited; }
  void Release();
private:
  Result Outcome {};
  uint64_t Executor {};
  bool Owned {}, Waited {};
};
// An actual registry hold for a foreign thread during owner-admitted cache
// invalidation. It grants no execution authority and cannot be used as the
// current thread's SourceLifetime. Only ContextImpl can acquire it.
class SourceInvalidationHold {
public:
  SourceInvalidationHold() = default;
  SourceInvalidationHold(const SourceInvalidationHold&) = delete;
  SourceInvalidationHold& operator=(const SourceInvalidationHold&) = delete;
  SourceInvalidationHold(SourceInvalidationHold&&) noexcept;
  ~SourceInvalidationHold();
  explicit operator bool() const { return Held; }
  Result Release();
private:
  friend class FEXCore::Context::ContextImpl;
  static SourceInvalidationHold Acquire(const SourceLifetime&, const FEXCore::Core::InternalThreadState*);
  uint64_t ContextSerial {}, BindingSerial {};
  uint32_t BindingIndex {};
  bool Held {};
};
static_assert(sizeof(SourceInvalidationHold) <= 32, "Bounded foreign source hold");
// Actual allocation/deletion owners alone admit Context identities. These are
// NX source lifecycle transitions, never Wine permissions or wire operations.
class SourceContextHold {
public:
  SourceContextHold() = default;
  SourceContextHold(const SourceContextHold&) = delete;
  SourceContextHold& operator=(const SourceContextHold&) = delete;
  SourceContextHold(SourceContextHold&&) noexcept;
  ~SourceContextHold();
  explicit operator bool() const { return Held; }
  Result Release();
private:
  friend class SourceLifecycle;
  const FEXCore::Context::Context* Object {};
  uint64_t Serial {};
  bool Held {};
};
static_assert(sizeof(SourceContextHold) <= 24, "Bounded real Context construction hold");
namespace Retirement { Result DrainAtNativeGate(); }
class SourceLifecycle {
private:
  friend class FEXCore::Context::ContextImpl;
  friend struct FEXCore::Context::PearContextDeleter;
  friend Result Retirement::DrainAtNativeGate();
  static Result Allocated(const FEXCore::Context::Context*);
  static SourceContextHold HoldContext(const FEXCore::Context::Context*);
  static Result CloseContext(const FEXCore::Context::Context*);
  static Result EnsureContextCleanupExecutor(const FEXCore::Context::Context*);
  // Only the exact detached ledger drain can request this cleanup. It grants
  // no Bootstrap shared reserve/write/pin/entry or caller-selected operation.
  static Result RetireDetachedAtCleanupGate(Allocation&);
  static Result CloseThread(const FEXCore::Context::Context*, const FEXCore::Core::InternalThreadState*);
  static Result AttachAllocatedThread(const FEXCore::Context::Context*, FEXCore::Core::InternalThreadState*, uint32_t);
  static Result SealThreadDelete(const FEXCore::Core::InternalThreadState*);
  static Result DeletedThread(const FEXCore::Core::InternalThreadState*);
  static Result SealContextDelete(const FEXCore::Context::Context*);
  static Result BeginContextDestruction(const FEXCore::Context::Context*);
  static Result Deleted(const FEXCore::Context::Context*);
  static void Retain(const FEXCore::Context::Context*, Result);
  static void RetainDestroyed(const FEXCore::Context::Context*, Result);
};
// A finite source-condition wait uses exact ntdll status, not a boolean wrapper
// that can discard a real error. No source/owner metadata lock is held here.
Result WaitSourceEntryChange(const std::atomic<uint32_t>& Word, uint32_t Expected, uint32_t Milliseconds);
void NotifySourceEntryChange(const std::atomic<uint32_t>& Word);

// All functions execute at qualified compiled native gates. The source caller
// obtains/revalidates its actual CPUArea/TLS ownership before use. These calls
// do not initialize FEX or manufacture a native thread/source context.
// Called by the existing Windows module with the actual matched ntdll and
// native helper-supplied Unix PID. This resolves a bridge; it creates no core.
Result Init(void* NtDll, uint64_t UnixOwnerPid);
// Bind the actual newly created Context before InitCore creates its dispatcher.
// Bootstrap ownership permits dispatcher construction only; it grants no JIT
// read/entry or arbitrary source-thread identity.
Result BindBootstrapContext(const FEXCore::Context::Context*);
Result BindSourceThread(const FEXCore::Core::InternalThreadState*);
// Call after the real Thread and its self-referencing frame exist, before
// InitializeCompiler. Only a matching bootstrap may transfer ownership through
// checked UNREGISTER followed by a new source-bound REGISTER.

uint32_t CurrentSourceRole();
// These checks clear only clean never-registered metadata. A malformed success
// does not imply unregistration; retain the actual source object when false.
bool SourceBindingCanRelease(const FEXCore::Core::InternalThreadState*);
bool SourceContextCanRelease(const FEXCore::Context::Context*);
// Cleanup-only native-idle observations preserve exact source identities and
// remain permitted after sticky admission closes. They grant no new work.
Result CheckBootstrapCleanup(const FEXCore::Context::Context*);
Result CheckThreadCleanup(const FEXCore::Core::InternalThreadState*);
// Primary registration/attach failure and its separate attempted cleanup are
// available for retained/quarantined bindings. A cleanup status alone cannot
// distinguish unperformed from an actual refusal; use CleanupWasAttempted too.
// The caller always retains the primary return value.
Result GetOriginalAttachFailure(const FEXCore::Core::InternalThreadState*);
Result GetOriginalAttachFailure(const FEXCore::Context::Context*);
Result GetCleanupOutcome(const FEXCore::Core::InternalThreadState*);
Result GetCleanupOutcome(const FEXCore::Context::Context*);
bool CleanupWasAttempted(const FEXCore::Core::InternalThreadState*);
bool CleanupWasAttempted(const FEXCore::Context::Context*);
Result DrainPendingRetirements();
Result RegisterExecutor(uint32_t SourceRole);
uint64_t CurrentExecutor();
Result UnregisterExecutor();
Allocation Reserve(size_t Size, uint32_t AllocationClass, uint32_t SourceRole);
Result Query(Allocation&);
Result Enter(const Allocation&, size_t EntryOffset, uint64_t Continuation = 0);
// NX-only proof for the current actual TEB/source/executor. A successful ENTRY
// records this exact allocation and entry offset. The proof is cleared before
// EXIT/HANDOFF/UNREGISTER and is unavailable during any native transition.
// This observes no code/protection and grants no new lease. A caller must also
// observe every covered page under the still-owned ACTIVE lease before copying.
bool HasManagedActive(const Allocation&);
// Ordinary compiled-native copying only, never a raw delivered handler. The
// caller supplies its actual source thread state and a preallocated NX record.
// Keep the same ACTIVE lease throughout all queries/copies; this grants no new
// lease and never broadens whole-extent QUERY for a mixed protection extent.
struct ManagedReadResult {
  Result Outcome {};
  size_t BytesCopied {};
  uint32_t SourcePagesObserved {};
  uint32_t DestinationPagesObserved {};
  explicit operator bool() const { return static_cast<bool>(Outcome); }
};
inline constexpr size_t MAX_MANAGED_READ_BYTES = 4096;
ManagedReadResult CopyManagedRX(const Allocation&, const void* ActualSourceThreadState,
                               size_t Offset, std::span<uint8_t> Destination);
// Only CPUBackend can mint this from its actual selected/retained CodeBuffer
// and that same object's TokenState. The shared reference pins source lifetime;
// a caller-selected metadata token cannot stand in for an owned source object.
class RetainedManagedTarget {
public:
  explicit operator bool() const { return Owner && SourceState && static_cast<bool>(Captured); }
private:
  friend class FEXCore::CPU::CPUBackend;
  RetainedManagedTarget(std::shared_ptr<FEXCore::CPU::CodeBuffer> ActualOwner,
                        const TokenState& ActualSourceState, const Allocation& Facts)
    : Owner(std::move(ActualOwner)), SourceState(&ActualSourceState), Captured(Facts) {}
  std::shared_ptr<FEXCore::CPU::CodeBuffer> Owner;
  const TokenState* SourceState {};
  Allocation Captured {};
  friend ManagedReadResult CopyManagedRXUnderGlobalLease(const Allocation&, const RetainedManagedTarget&,
    const void*, size_t, std::span<uint8_t>);
};
// A checked dispatcher ACTIVE lease prevents every managed write/retirement.
// This separate API preserves the exact-extent CopyManagedRX contract: target
// JIT bytes still need actual retained source identity and per-page RX proof.
ManagedReadResult CopyManagedRXUnderGlobalLease(const Allocation& ProtectionD, const RetainedManagedTarget&,
  const void* ActualSourceThreadState, size_t Offset, std::span<uint8_t> Destination);
Result Exit(const Allocation&);
Result Pin(const Allocation&, size_t ResumeOffset, uint64_t& Continuation);
Result Unpin(const Allocation&, uint64_t Continuation, uint64_t PinEpoch);
// Paired ABI2 owner transition only. The source caller must separately hold
// a sealed entry reservation and the actual Context/Thread/Dispatcher lifetime.
// This leaf does not manufacture those source proofs or authorize a raw handler.
Result Resume(const Allocation& CurrentD, size_t OriginalResumeOffset,
              uint64_t OriginalContinuation, uint64_t OriginalPinEpoch);
Result Handoff(const Allocation&, size_t ResumeOffset, uint64_t& Continuation);
// Poll only an already-owned native handoff. The original pin epoch is explicit
// and must survive any later writer epoch; it is never inferred from Allocation.
// The existing opcode-13 size-zero case creates no new descriptor or pin.
Result Poll(const Allocation&, size_t ResumeOffset, uint64_t Continuation, uint64_t OriginalPinEpoch);
Result Retire(Allocation&);

// Construct before holding invalidation/lookup/list/ThreadCreation locks.
// BeginWrite closes the owner gate and waits at the native gate before granting
// RWNX. No separate unchecked global-write-lock operation exists in ABI1.
class WriteGuard {
public:
  WriteGuard(Allocation&, size_t Offset, size_t Size, uint64_t Continuation = 0);
  ~WriteGuard();
  WriteGuard(const WriteGuard&) = delete;
  WriteGuard& operator=(const WriteGuard&) = delete;
  explicit operator bool() const { return Outcome.Status == PEAR_FEX_OK && Open; }
  uint8_t* Data() const { return Open ? WriteBase : nullptr; }
  Result Status() const { return Outcome; }
  bool Matches(size_t RelativeOffset, std::span<const uint8_t> Expected) const;
  Result Publish();
  Result Abort();
private:
  Allocation& Owner;
  pear_fex_memory_request Request {};
  uint8_t* WriteBase {};
  size_t WindowSize {};
  bool Open {};
  Result Outcome {};
};
} // namespace FEXCore::Utils::PearFEXMemory
