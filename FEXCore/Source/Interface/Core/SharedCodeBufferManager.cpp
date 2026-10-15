// SPDX-License-Identifier: MIT
#include "Interface/Core/LookupCache.h"
#include "Interface/Core/SharedCodeBufferManager.h"

#include <FEXCore/fextl/memory.h>
#include <FEXCore/Utils/AllocatorHooks.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MathUtils.h>
#ifdef PEAR_FEX_MEMORY_OWNER
#include <utility>
#include <FEXCore/Utils/PearDataMemory.h>
#include <FEXCore/Utils/PearSourceGuard.h>
#endif

#ifndef _WIN32
#include <FEXCore/Utils/PrctlUtils.h>
#endif

namespace FEXCore::CPU {
static constexpr size_t INITIAL_CODE_SIZE = 1024 * 1024 * 16;
// We don't want to move above 128MB atm because that means we will have to encode longer jumps
static constexpr size_t MAX_CODE_SIZE = 1024 * 1024 * 128;

CodeBuffer::CodeBuffer(size_t Size, bool ShouldBeNamed)
  : AllocatedSize(Size) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // The source factory performs observed owner operations and returns their
  // exact Result. This constructor creates no hidden executable allocation.
#else
  Ptr = static_cast<uint8_t*>(FEXCore::Allocator::VirtualAlloc(Size, true));
  LOGMAN_THROW_A_FMT(!!Ptr, "Couldn't allocate code buffer");

  // Protect the last page of the allocated buffer to trigger SIGSEGV on write access
  uintptr_t LastPageAddr = AlignDown(reinterpret_cast<uintptr_t>(Ptr) + Size - 1, FEXCore::Utils::FEX_PAGE_SIZE);
  if (!FEXCore::Allocator::VirtualProtect(reinterpret_cast<void*>(LastPageAddr), FEXCore::Utils::FEX_PAGE_SIZE,
                                          FEXCore::Allocator::ProtectOptions::None)) {
    LogMan::Msg::EFmt("Failed to mprotect last page of code buffer.");
  }

  if (ShouldBeNamed) {
    FEXCore::Allocator::VirtualName("FEXMemJIT", Ptr, Size);
  }

  // Huge-pages reduce the amount of iTLB misses dramatically when it works.
  FEXCore::Allocator::VirtualTHPControl(Ptr, Size, FEXCore::Allocator::THPControl::Enable);

#endif

#ifndef PEAR_FEX_MEMORY_OWNER
  LookupCache = fextl::make_unique<GuestToHostMap>();
  CodeBufferEnd = Ptr + UsableSize();
  CodeBufferOffset = Ptr;
#endif
}

#ifdef PEAR_FEX_MEMORY_OWNER
FEXCore::Utils::PearFEXMemory::Result CodeBuffer::InitializePear() {
  namespace Memory = FEXCore::Utils::PearFEXMemory;
  if (!Memory::Retirement::AdmissionOpen()) return Memory::Retirement::FirstFailureSnapshot().Outcome;
  if (!Memory::CurrentExecutor() || Memory::CurrentSourceRole() != PEAR_SOURCE_CODE_ROLE)
    return {PEAR_FEX_UNAVAILABLE, 0, 0};
  auto Allocation = Memory::Reserve(AllocatedSize, PEAR_FEX_CLASS_SHARED, PEAR_SOURCE_CODE_ROLE);
  if (!Allocation) return {Allocation.Status, Allocation.ErrorDomain, Allocation.ErrorCode};
  const auto Empty = GetPearSnapshot();
  if (!ComparePearUpdate(Empty, Allocation)) return Memory::Retirement::PoisonSourceAdmission({PEAR_FEX_STALE_IDENTITY, 0, 0});
  Memory::WriteGuard InitialWindow {Allocation, 0, 16};
  if (!InitialWindow) {
    const auto Original = InitialWindow.Status();
    Memory::Retirement::PoisonSourceAdmission(Original);
    return Original;
  }
  auto* LearnedBase = InitialWindow.Data();
  const auto BeforeAbort = GetPearSnapshot();
  const auto Aborted = InitialWindow.Abort();
  if (!ComparePearUpdate(BeforeAbort, Allocation)) return Memory::Retirement::PoisonSourceAdmission({PEAR_FEX_STALE_IDENTITY, 0, 0});
  if (!Aborted) { Memory::Retirement::PoisonSourceAdmission(Aborted); return Aborted; }
  if (!LearnedBase || Allocation.Base || Allocation.Token.expected_state != PEAR_FEX_RESERVED_NONE)
    return Memory::Retirement::PoisonSourceAdmission({PEAR_FEX_VERSION_MISMATCH, 0, 0});
  Ptr = LearnedBase;
  LookupCache = FEXCore::Allocator::TryMakePearMetadataObject<GuestToHostMap>();
  if (!LookupCache) return {PEAR_FEX_UNAVAILABLE,0,0};
  CodeBufferEnd = Ptr + UsableSize();
  CodeBufferOffset = Ptr;
  return {PEAR_FEX_OK, 0, 0};
}
namespace {
// Prechecked storage still uses the real shared_ptr control block. Its allocator
// survives the managed object until the final weak reference is released.
template<typename T> struct PearControlAllocator {
  using value_type=T;
  void* Storage;
  explicit PearControlAllocator(void* P) : Storage {P} {}
  template<typename U> PearControlAllocator(const PearControlAllocator<U>& Other) : Storage {Other.Storage} {}
  T* allocate(size_t Count) {
    static_assert(sizeof(T)<=256 && alignof(T)<=16);
    PEAR_FEX_REQUIRE(Count==1 && Storage,"Code-buffer control allocation shape");
    return static_cast<T*>(Storage);
  }
  void deallocate(T* P,size_t Count) {
    PEAR_FEX_REQUIRE(P==Storage && Count==1,"Code-buffer control allocation identity");
    FEXCore::Allocator::FreePearMetadataOrHeap(P);
  }
  template<typename U> bool operator==(const PearControlAllocator<U>& Other) const { return Storage==Other.Storage; }
};
}
fextl::shared_ptr<CodeBuffer> CodeBuffer::CreatePear(size_t Size, bool Named, FEXCore::Utils::PearFEXMemory::Result& Outcome) {
  Outcome={PEAR_FEX_UNAVAILABLE,0,0};
  void* Storage=FEXCore::Allocator::AllocatePearMetadataStorage(16,256);
  if (!Storage) return {};
  auto Buffer = std::allocate_shared<CodeBuffer>(PearControlAllocator<CodeBuffer> {Storage},Size,Named);
  Outcome = Buffer->InitializePear();
  // A failed shell's destructor retains any exact detached allocation facts;
  // no unchecked pointer or partially initialized LookupCache is published.
  return Outcome ? Buffer : fextl::shared_ptr<CodeBuffer> {};
}
#endif

CodeBuffer::~CodeBuffer() {
#ifdef PEAR_FEX_MEMORY_OWNER
  // A last shared_ptr release can occur beneath an upstream list/lookup or
  // ThreadCreation lock. Detach only NX facts here; the native gate performs
  // the exact owner retirement after all source locks have been released.
  const auto Facts = GetPearSnapshot();
  if (!Facts.Token.allocation_id) return;
  const auto Detached = FEXCore::Utils::PearFEXMemory::Retirement::EnqueueDetached(Facts);
  if (!Detached) LogMan::Msg::EFmt("Pear code-buffer retirement enqueue refused: status {}, domain {}, code {}",
                                  Detached.Status, Detached.ErrorDomain, Detached.ErrorCode);
#else
  FEXCore::Allocator::VirtualFree(Ptr, AllocatedSize);
#endif
}

SharedCodeBufferManager::SharedCodeBufferManager() {
  FEX_CONFIG_OPT(GlobalJITNaming, GLOBALJITNAMING);
  FEX_CONFIG_OPT(LibraryJITNaming, LIBRARYJITNAMING);
  FEX_CONFIG_OPT(BlockJITNaming, BLOCKJITNAMING);

  // Only name the JIT buffers if perf JIT naming is disabled.
  // `perf top` prefers VMA names over the JIT symbols file for some reason.
  // Breaks memory tracking when naming is enabled, but it's a debug feature so it isn't expected to be enabled by default.
  NameJITBuffers = !(GlobalJITNaming || LibraryJITNaming || BlockJITNaming);
}

fextl::shared_ptr<CodeBuffer> SharedCodeBufferManager::AllocateNew(size_t Size) {
#ifdef PEAR_FEX_MEMORY_OWNER
  FEXCore::Utils::PearFEXMemory::Result Outcome;
  return AllocatePearNew(Size, Outcome);
#else
#ifndef _WIN32
  // MDWE (Memory-Deny-Write-Execute) is a new Linux 6.3 feature.
  // It's equivalent to systemd's `MemoryDenyWriteExecute` but implemented entirely in the kernel.
  //
  // MDWE prevents applications from creating RWX memory mappings.
  // This prevents FEX from doing anything JIT related, as FEX uses RWX for JIT memory mappings.
  //
  // A potential workaround to make FEX work with MDWE is to call mprotect every time we need to write or modify code.
  // Alternatively, FEX could use a memory mirror where one half is mapped as RW and the other is RX.
  //
  // Once MDWE is enabled with the prctl, the feature is sealed and it can /NOT/ be turned off.
  //
  // Status of MDWE is queried through prctl using `PR_GET_MDWE`:
  // -1: The kernel doesn't support MDWE
  // 0: MDWE is supported but disabled
  // >0: MDWE is enabled, hence prohibiting RWX mappings
  int MDWE = ::prctl(PR_GET_MDWE, 0, 0, 0, 0);
  if (MDWE != -1 && MDWE != 0) {
    LogMan::Msg::EFmt("MDWE was set to 0x{:x} which means FEX can't allocate executable memory", MDWE);
  }
#endif

  auto Buffer = fextl::make_shared<CodeBuffer>(Size, NameJITBuffers);
  Latest = Buffer;
  OnCodeBufferAllocated(Buffer);
  return Buffer;
#endif
}
#ifdef PEAR_FEX_MEMORY_OWNER
fextl::shared_ptr<CodeBuffer> SharedCodeBufferManager::AllocatePearNew(size_t Size, FEXCore::Utils::PearFEXMemory::Result& Outcome) {
  auto Buffer = CodeBuffer::CreatePear(Size, NameJITBuffers, Outcome);
  if (!Buffer) return {};
  fextl::shared_ptr<CodeBuffer> Previous;
  {
    std::scoped_lock Lock {PearLatestMutex};
    Previous = std::exchange(Latest, Buffer);
  }
  OnCodeBufferAllocated(Buffer);
  Previous.reset();
  return Buffer;
}
fextl::shared_ptr<CodeBuffer> SharedCodeBufferManager::GetPearLatest(FEXCore::Utils::PearFEXMemory::Result& Outcome) {
  namespace Memory = FEXCore::Utils::PearFEXMemory;
  if (!Memory::Retirement::AdmissionOpen()) { Outcome = Memory::Retirement::FirstFailureSnapshot().Outcome; return {}; }
  if (Memory::CurrentSourceRole() != PEAR_SOURCE_CODE_ROLE) { Outcome = {PEAR_FEX_UNAVAILABLE, 0, 0}; return {}; }
  fextl::shared_ptr<CodeBuffer> Snapshot;
  { std::scoped_lock Lock {PearLatestMutex}; Snapshot = Latest; }
  if (Snapshot) { Outcome = {PEAR_FEX_OK, 0, 0}; return Snapshot; }
  return AllocatePearNew(INITIAL_CODE_SIZE, Outcome);
}
bool SharedCodeBufferManager::HasPearLatest() {
  std::scoped_lock Lock {PearLatestMutex}; return !!Latest;
}
void SharedCodeBufferManager::DetachPearLatest() {
  fextl::shared_ptr<CodeBuffer> Detached;
  { std::scoped_lock Lock {PearLatestMutex}; Detached = std::exchange(Latest, {}); }
  Detached.reset();
}
#endif

fextl::shared_ptr<CodeBuffer> SharedCodeBufferManager::GetLatest() {
#ifdef PEAR_FEX_MEMORY_OWNER
  FEXCore::Utils::PearFEXMemory::Result Outcome;
  return GetPearLatest(Outcome);
#else
  if (!Latest) {
    AllocateNew(INITIAL_CODE_SIZE);
  }
  return Latest;
#endif
}

fextl::shared_ptr<CodeBuffer> SharedCodeBufferManager::StartLargerCodeBuffer() {
#ifdef PEAR_FEX_MEMORY_OWNER
  const auto Current = GetLatest();
  if (!Current) return {};
  const auto Size = std::min<size_t>(Current->TotalAllocationSize()*2, MAX_CODE_SIZE);
  return AllocateNew(Size);
#else
  if (!Latest) {
    // Allocate initial CodeBuffer and return it
    return GetLatest();
  }

  auto NewCodeBufferSize = GetLatest()->TotalAllocationSize();
  NewCodeBufferSize = std::min<size_t>(NewCodeBufferSize * 2, MAX_CODE_SIZE);
  return AllocateNew(NewCodeBufferSize);
#endif
}

fextl::shared_ptr<CodeBuffer> SharedCodeBufferManager::StartMaximalCodeBuffer() {
  return AllocateNew(MAX_CODE_SIZE);
}
} // namespace FEXCore::CPU
