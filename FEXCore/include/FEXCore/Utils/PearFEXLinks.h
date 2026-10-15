// SPDX-License-Identifier: MIT
// Private paired-source NX observations. No owner permission or wire change.
#pragma once
#include <FEXCore/Utils/PearFEXMemory.h>
namespace FEXCore::Context { class Context; }
namespace FEXCore::CPU::PearJITLinks { struct Registry; }
namespace FEXCore::Utils::PearFEXMemory::Links {
// A source lifetime reference, not permission/quiescence. Only the actual
// backend can mint it from its actual CurrentCodeBuffer/Thread and token.
class ReservedBarrierTarget {
public:
  explicit operator bool() const { return Owner && ActualThread && Captured && Captured.Token.expected_state==PEAR_FEX_RESERVED_NONE; }
private:
  friend class FEXCore::CPU::CPUBackend;
  friend struct FEXCore::CPU::PearJITLinks::Registry;
  ReservedBarrierTarget(std::shared_ptr<FEXCore::CPU::CodeBuffer> Source,const Allocation& Facts,
                        const FEXCore::Core::InternalThreadState* Thread)
    : Owner(std::move(Source)),Captured(Facts),ActualThread(Thread) {}
  std::shared_ptr<FEXCore::CPU::CodeBuffer> Owner;
  Allocation Captured;
  const FEXCore::Core::InternalThreadState* ActualThread {};
};
// A short NX reservation minted only from a held actual source lifetime.
// It blocks new Prepared/batch transitions until actual atomic resume and
// expected-byte acceptance finish. It grants no owner or VM permission.
class SealedEntry {
public:
  SealedEntry() = default;
  SealedEntry(const SealedEntry&) = delete;
  SealedEntry& operator=(const SealedEntry&) = delete;
  SealedEntry(SealedEntry&&) noexcept;
  ~SealedEntry();
  explicit operator bool() const { return Value; }
  Result Validate(const SourceLifetime&) const;
  Result Release();
private:
  friend Result TrySealEntry(const SourceLifetime&, SealedEntry&);
  uint64_t Value {};
  uint32_t Index {};
};
static_assert(sizeof(SealedEntry)<=16,"Bounded source entry ticket");
Result TrySealEntry(const SourceLifetime&, SealedEntry&);
bool EntryResumeAdmitted(const SourceLifetime&);
uint32_t EntrySequence();
Result WaitForEntryChange(uint32_t Expected, uint32_t Milliseconds);
bool EntryAdmissionOpen();
Result FirstFailureSnapshot();
bool HasOutstanding(const FEXCore::Context::Context*);
// Thread cleanup excludes shared code descriptors, which own Context/buffer
// references but no ThreadState pointer. Actual entry/batch references block it.
bool HasOutstanding(const FEXCore::Context::Context*, const FEXCore::Core::InternalThreadState*);
bool MutationAdmitted(const FEXCore::Context::Context*);
}
