// SPDX-License-Identifier: MIT
/*
$info$
category: backend ~ IR to host code generation
tags: backend|shared
$end_info$
*/

#pragma once

#include "Interface/Core/SharedCodeBufferManager.h"

#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/Utils/SignalScopeGuards.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/vector.h>
#include <FEXCore/fextl/map.h>

#include <cstdint>
#include <span>
#ifdef PEAR_FEX_MEMORY_OWNER
#include <optional>
#include <FEXCore/Utils/PearFEXLinks.h>
#endif

namespace FEXCore::CPU {
union Relocation;
}

namespace FEXCore {

namespace IR {
  class IRListView;
} // namespace IR

namespace Core {
  struct DebugData;
  struct ThreadState;
  struct CpuStateFrame;
  struct InternalThreadState;
} // namespace Core

namespace CodeSerialize {
  struct CodeObjectFileSection;
}

struct GuestToHostMap;

namespace CPU {
  class CPUBackend {
  public:

    CPUBackend(SharedCodeBufferManager&, FEXCore::Core::InternalThreadState*);

    virtual ~CPUBackend();

    struct CompiledCode {
      // Where this code block begins.
      uint8_t* BlockBegin;
      fextl::map<uint64_t, uint8_t*> EntryPoints;
      // The total size of the codeblock from [BlockBegin, BlockBegin+Size).
      size_t Size;
      // Offset of BlockBegin from the start of the CodeBuffer it lives in
      uint64_t HostCodeOffset;
#ifdef PEAR_FEX_MEMORY_OWNER
      // Pending pointers refer only to private NX emission and are not cacheable.
      bool PearPendingEmission {};
      bool PearOwnerPublished {};
#endif
    };

    // Header that can live at the start of a JIT block.
    // We want the header to be quite small, with most data living in the tail object.
    struct JITCodeHeader {
      // Offset from the start of this header to where the tail lives.
      // Only 32-bit since the tail block won't ever be more than 4GB away.
      uint32_t OffsetToBlockTail;
    };

    // Header that can live at the end of the JIT block.
    // For any state reconstruction or other data, this is where it should live.
    // Any data that is explicitly tied to the JIT code and needs to be cached with it
    // should end up in this data structure.
    struct JITCodeTail {
      // The total size of the codeblock from [BlockBegin, BlockBegin+Size).
      size_t Size;

      // RIP that the block's entry comes from.
      uint64_t RIP;

      // The length of the guest code for this block.
      size_t GuestSize;

      // Number of RIP entries for this JIT Code section.
      uint32_t NumberOfRIPEntries;

      // Offset after this block to the start of the RIP entries.
      uint32_t OffsetToRIPEntries;

      // Shared-code modification spin-loop futex.
      uint32_t SpinLockFutex;

      // If this block represents a single guest instruction.
      bool SingleInst;

      uint8_t _Pad[3];
    };

    /**
     * @brief Tells this CPUBackend to compile code for the provided IR and DebugData
     *
     * The returned pointer needs to be long lived and be executable in the host environment
     * FEXCore's frontend will store this pointer in to a cache for the current RIP when this was executed
     *
     * This is a thread specific compilation unit since there is one CPUBackend per guest thread
     *
     * @param Size - The byte size of the guest code for this block
     * @param SingleInst - If this block represents a single guest instruction
     * @param IR -  IR that maps to the IR for this RIP
     * @param DebugData - Debug data that is available for this IR indirectly
     * @param CheckTF - If EFLAGS.TF checks should be emitted at the start of the block
     *
     * @return Information about the compiled code block.
     */
    [[nodiscard]]
    virtual CompiledCode CompileCode(uint64_t Entry, uint64_t Size, bool SingleInst, const FEXCore::IR::IRListView* IR,
                                     FEXCore::Core::DebugData* DebugData, bool CheckTF) = 0;

#ifdef PEAR_FEX_MEMORY_OWNER
    // Begin is called outside invalidation/list/lookup/thread-creation locks.
    // Finish runs only after the caller reacquires/revalidates its source lease.
    virtual bool BeginPreparedPublication(CompiledCode&) { return false; }
    virtual bool FinishPreparedPublication(CompiledCode&, bool SourceStillValid) { return false; }
    virtual void DiscardPreparedPublication() {}
#endif
    virtual CompiledCode LoadCachedCode(std::span<const uint8_t> HostBytes) {
      return {};
    }

    virtual fextl::vector<FEXCore::CPU::Relocation> TakeRelocations(uint64_t GuestBaseAddress) = 0;

    virtual void ClearCache() {}

    /**
     * @brief Clear any relocations after JIT compiling
     */
    virtual void ClearRelocations() {}

    bool IsAddressInCodeBuffer(uintptr_t Address) const;
#ifdef PEAR_FEX_MEMORY_OWNER
    // Numeric metadata only: callers retain this exact source generation before
    // reading an instruction/tail under an independently admitted active lease.
    struct PearManagedWindow {
      fextl::shared_ptr<CodeBuffer> Owner;
      FEXCore::Utils::PearFEXMemory::Allocation Facts;
      uintptr_t Begin;
      size_t Size;
      size_t Offset;
    };
    // Private original ARM64 fixture in this backend's actual empty generation.
    // No IR translation, guest dispatch or caller-provided code bytes.
    FEXCore::Utils::PearFEXMemory::Result PreparePearFiniteCode();
    std::optional<PearManagedWindow> FindPearManagedWindow(uintptr_t PC) const;
    // Actual current published source buffer, including one with no direct links.
    std::optional<PearManagedWindow> FindPearPublishedBarrierTarget() const;
    // The thin target constructor is friend-only. No caller-supplied tuple or
    // pointer can substitute for this backend's actual retained CodeBuffer.
    std::optional<FEXCore::Utils::PearFEXMemory::RetainedManagedTarget> FindPearRetainedTarget(uintptr_t PC) const;
    std::optional<FEXCore::Utils::PearFEXMemory::Links::ReservedBarrierTarget> FindPearReservedBarrierTarget() const;
#endif

    // Updates the CodeBuffer if needed and returns a reference to the old one.
    // The returned reference should be kept alive carefully to avoid early deletion of resources.
    [[nodiscard]]
    fextl::shared_ptr<CodeBuffer> CheckCodeBufferUpdate();

  protected:
    // Max spill slot size in bytes. We need at most 32 bytes
    // to be able to handle a 256-bit vector store to a slot.
    constexpr static uint32_t MaxSpillSlotSize = 32;

    FEXCore::Core::InternalThreadState* ThreadState;

    // Acquires a new shared code buffer, setting `CurrentCodeBuffer` and returning a pointer to it.
    [[nodiscard]]
    CodeBuffer* AcquireNewSharedCodeBuffer();

    // This is the code buffer containing the main code under execution by this thread.
    // CheckCodeBufferUpdate must be used before compiling new code.
    fextl::shared_ptr<CodeBuffer> CurrentCodeBuffer;

    // Old CodeBuffer generations required to be valid until returning from signal handlers
    fextl::vector<fextl::shared_ptr<CodeBuffer>> SignalHandlerCodeBuffers;

    SharedCodeBufferManager& SharedCodeBuffers;

  private:
    void RegisterForSignalHandler(fextl::shared_ptr<CodeBuffer>);
  };

} // namespace CPU
} // namespace FEXCore
