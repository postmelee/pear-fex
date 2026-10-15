// SPDX-License-Identifier: MIT
/*
$info$
category: code buffer ~ Thread shared code buffer management
tags: backend|shared
$end_info$
*/
#pragma once

#include <FEXCore/fextl/memory.h>
#ifdef PEAR_FEX_MEMORY_OWNER
#include <FEXCore/Utils/PearSourceGuard.h>
#include <FEXCore/Utils/PearFEXMemory.h>
#include <FEXCore/Utils/PearFEXRetirement.h>
#endif
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/SignalScopeGuards.h>
#include <FEXCore/Utils/TypeDefines.h>

#include <cstddef>
#include <cstdint>
#ifdef PEAR_FEX_MEMORY_OWNER
#include <mutex>
#endif

namespace FEXCore {
struct GuestToHostMap;
}

namespace FEXCore::CPU {
#ifdef PEAR_FEX_MEMORY_OWNER
#ifdef ARCHITECTURE_arm64ec
inline constexpr uint32_t PEAR_SOURCE_CODE_ROLE = PEAR_FEX_ROLE_ARM64EC;
#else
inline constexpr uint32_t PEAR_SOURCE_CODE_ROLE = PEAR_FEX_ROLE_NATIVE;
#endif
#endif
struct CodeBuffer {
  fextl::unique_ptr<GuestToHostMap> LookupCache;

  CodeBuffer(size_t Size, bool ShouldBeNamed);
#ifdef PEAR_FEX_MEMORY_OWNER
  static fextl::shared_ptr<CodeBuffer> CreatePear(size_t, bool, FEXCore::Utils::PearFEXMemory::Result&);
#endif
  CodeBuffer(const CodeBuffer&) = delete;
  CodeBuffer& operator=(const CodeBuffer&) = delete;
  CodeBuffer(CodeBuffer&& oth) = delete;
  CodeBuffer& operator=(CodeBuffer&&) = delete;

  ~CodeBuffer();

  // Atomically allocate a fixed size buffer out of the current allocated codebuffer.
  // Lockless because it's just a linear allocator.
  struct CodeBufferAllocation {
    const uint8_t* BufferBase;
    uint8_t* BufferAllocationOffset;
#ifdef PEAR_FEX_MEMORY_OWNER
    CodeBuffer* Owner;
#endif
  };

  CodeBufferAllocation AtomicAllocateBuffer(size_t Size) {
#ifdef PEAR_FEX_MEMORY_OWNER
    // An exhausted or overflowing request never wraps a metadata pointer.
    if (!Size || Size > UsableSize() || Size > SIZE_MAX - 15) return {};
#endif
    Size = FEXCore::AlignUp(Size, 16);
#ifdef PEAR_FEX_MEMORY_OWNER
    PEAR_FEX_REQUIRE(reinterpret_cast<uintptr_t>(CodeBufferOffset.load()) % 16 == 0, "Buffer needs to always be 16B aligned!");
#else
    LOGMAN_THROW_A_FMT(reinterpret_cast<uintptr_t>(CodeBufferOffset.load()) % 16 == 0, "Buffer needs to always be 16B aligned!");
#endif

    auto ExpectedOffset = CodeBufferOffset.load(std::memory_order_relaxed);
#ifdef PEAR_FEX_MEMORY_OWNER
    if (ExpectedOffset > CodeBufferEnd || Size > static_cast<size_t>(CodeBufferEnd - ExpectedOffset)) return {};
#endif
    auto DesiredOffset = ExpectedOffset + Size;

    if (DesiredOffset > CodeBufferEnd) {
      // Couldn't fit.
      return {};
    }

    while (!CodeBufferOffset.compare_exchange_strong(ExpectedOffset, DesiredOffset)) {
#ifdef PEAR_FEX_MEMORY_OWNER
      if (ExpectedOffset > CodeBufferEnd || Size > static_cast<size_t>(CodeBufferEnd - ExpectedOffset)) return {};
#endif
      DesiredOffset = ExpectedOffset + Size;

      if (DesiredOffset > CodeBufferEnd) {
        // Couldn't fit.
        return {};
      }
    }

    // Managed to fit.
    return {
      .BufferBase = Ptr,
      .BufferAllocationOffset = ExpectedOffset,
#ifdef PEAR_FEX_MEMORY_OWNER
      .Owner = this,
#endif
    };
  }

  // Returns the total number of bytes available for storing code
  size_t UsableSize() const {
    return AllocatedSize - FEXCore::Utils::FEX_PAGE_SIZE;
  }

  // Returns the full size of the buffer, including the guard page.
  size_t TotalAllocationSize() const {
    return AllocatedSize;
  }

  // Returns the num of bytes currently allocated from the allocator.
  size_t AllocatedSpaceUsed() const {
    return CodeBufferOffset - Ptr;
  }

  // Trivially reset the allocator.
  void Reset() {
    CodeBufferOffset = Ptr;
  }

  // Returns the base of the buffer.
  uint8_t* GetBufferBase() const {
    return Ptr;
  }

#ifdef PEAR_FEX_MEMORY_OWNER
  FEXCore::Utils::PearFEXMemory::Allocation GetPearSnapshot() const { return PearToken.Snapshot(); }
  const FEXCore::Utils::PearFEXMemory::TokenState& GetPearTokenState() const { return PearToken; }
  bool ComparePearUpdate(const FEXCore::Utils::PearFEXMemory::Allocation& Expected,
                         const FEXCore::Utils::PearFEXMemory::Allocation& Next) {
    return PearToken.CompareUpdate(Expected, Next);
  }
#endif

private:
#ifdef PEAR_FEX_MEMORY_OWNER
  FEXCore::Utils::PearFEXMemory::Result InitializePear();
  FEXCore::Utils::PearFEXMemory::TokenState PearToken {};
#endif
  uint8_t* Ptr {};
  uint8_t* CodeBufferEnd {};
  size_t AllocatedSize; // including guard page; see UsableSize()

  // Code buffer allocation information.
  std::atomic<uint8_t*> CodeBufferOffset {};
};

/**
 * A manager that coordinates access to the CodeBuffer used for compiling new code across threads.
 *
 * The CodeBuffer is managed as a partially persistent data structure:
 * - Exactly one CodeBuffer is now designated as "active", which means data can be appended to it
 * - Lossy modifications to the active CodeBuffer will not invalidate any data in use by other threads (which is what enables save CodeBuffer sharing across threads)
 * - Instead, such lossy modifications trigger a new "version" of the data in the modifying thread. Old versions of the CodeBuffer persist as read-only data for use by the other threads.
 * - The other threads can update their version of the CodeBuffer. This will decrease the reference count and eventually trigger deallocation of the old version
 */
class SharedCodeBufferManager {
public:
  SharedCodeBufferManager();
  virtual ~SharedCodeBufferManager() = default;

  // Get the CodeBuffer that was most recently allocated.
  // This is the only CodeBuffer that data may be written to.
  fextl::shared_ptr<CodeBuffer> GetLatest();
#ifdef PEAR_FEX_MEMORY_OWNER
  fextl::shared_ptr<CodeBuffer> GetPearLatest(FEXCore::Utils::PearFEXMemory::Result&);
  // Construction failure only, while its actual binding remains alive.
  void DetachPearLatest();
  bool HasPearLatest();
#endif

  // Allocate a new CodeBuffer with geometric growth up to an internal maximum.
  // Subsequent calls to GetLatest will point to the returned buffer.
  fextl::shared_ptr<CodeBuffer> StartLargerCodeBuffer();

  // Allocate a new CodeBuffer with maximum internal size.
  // Subsequent calls to GetLatest will point to the returned buffer.
  fextl::shared_ptr<CodeBuffer> StartMaximalCodeBuffer();

  virtual void OnCodeBufferAllocated(const std::shared_ptr<CodeBuffer>&) {};

private:
  fextl::shared_ptr<CodeBuffer> Latest;
#ifdef PEAR_FEX_MEMORY_OWNER
  // Holds only shared_ptr copies/exchanges. Never construct, wait, invoke
  // callbacks or destroy an old owner generation while this mutex is held.
  std::mutex PearLatestMutex;
#endif

  fextl::shared_ptr<CodeBuffer> AllocateNew(size_t Size);
#ifdef PEAR_FEX_MEMORY_OWNER
  fextl::shared_ptr<CodeBuffer> AllocatePearNew(size_t, FEXCore::Utils::PearFEXMemory::Result&);
#endif

  bool NameJITBuffers {true};
};
} // namespace FEXCore::CPU
