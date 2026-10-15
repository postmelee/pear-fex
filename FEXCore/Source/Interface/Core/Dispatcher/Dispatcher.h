// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Utils/PearSourceGuard.h>
#include "Interface/Core/ArchHelpers/Arm64Emitter.h"
#include "Interface/Core/Interpreter/InterpreterOps.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/fextl/memory.h>
#ifdef PEAR_FEX_MEMORY_OWNER
#include <FEXCore/Utils/PearFEXMemory.h>
#include <FEXCore/Utils/PearFEXRetirement.h>
#ifdef VIXL_SIMULATOR
#error Pear owner source hooks require the selected native dispatcher.
#endif
#endif

#include <array>
#include <cstddef>
#include <cstdint>

namespace FEXCore {
struct GuestSigAction;
struct SignalDelegatorConfig;
} // namespace FEXCore

namespace FEXCore::Core {
struct CpuStateFrame;
struct InternalThreadState;
} // namespace FEXCore::Core

namespace FEXCore::Context {
class ContextImpl;
}

namespace FEXCore::CPU {

#define STATE_PTR(STATE_TYPE, FIELD) STATE.R(), offsetof(FEXCore::Core::STATE_TYPE, FIELD)
#define STATE_PTR_IDX(STATE_TYPE, FIELD, INDEX) STATE.R(), ARRAY_OFFSETOF(FEXCore::Core::STATE_TYPE, FIELD, INDEX)
#define FALLBACK_HANDLER_OFFSET(INDEX, FIELD) \
  STATE.R(),                                  \
    (ARRAY_OFFSETOF(FEXCore::Core::CpuStateFrame, Pointers.FallbackHandlerPointers, INDEX) + offsetof(FEXCore::Core::FallbackABIInfo, FIELD))

class Dispatcher final : public Arm64Emitter {
public:
  static fextl::unique_ptr<Dispatcher> Create(FEXCore::Context::ContextImpl* CTX);
#ifdef PEAR_FEX_MEMORY_OWNER
  static fextl::unique_ptr<Dispatcher> CreatePear(FEXCore::Context::ContextImpl*, FEXCore::Utils::PearFEXMemory::Result&);
#endif

  Dispatcher(FEXCore::Context::ContextImpl* ctx);
  ~Dispatcher();

  void InitThreadPointers(FEXCore::Core::InternalThreadState* Thread);

#ifdef VIXL_SIMULATOR
  void ExecuteDispatch(FEXCore::Core::CpuStateFrame* Frame);
  void ExecuteJITCallback(FEXCore::Core::CpuStateFrame* Frame, uint64_t RIP);
#else
  void ExecuteDispatch(FEXCore::Core::CpuStateFrame* Frame) {
#ifdef PEAR_FEX_MEMORY_OWNER
    PEAR_FEX_REQUIRE(FEXCore::Utils::PearFEXMemory::Retirement::AdmissionOpen(), "Pear source retirement admission is closed");
    const auto Facts = GetPearSnapshot();
    const auto Base = reinterpret_cast<uintptr_t>(Facts.Base);
    const auto Address = reinterpret_cast<uintptr_t>(DispatchPtr);
    PEAR_FEX_REQUIRE(Facts && Facts.Token.expected_state == PEAR_FEX_PUBLISHED_RX &&
                      Facts.Token.allocation_class == PEAR_FEX_CLASS_DISPATCHER && Address >= Base &&
                      Address-Base < Facts.Token.extent_size && !(Address & 3), "Pear dispatcher entry range unavailable");
    const auto Entered = FEXCore::Utils::PearFEXMemory::Enter(Facts, Address-Base);
    PEAR_FEX_REQUIRE_RESULT(!!Entered, "Pear dispatcher entry refused: status {}, domain {}, code {}", Entered);
#endif
    DispatchPtr(Frame, false);
#ifdef PEAR_FEX_MEMORY_OWNER
    const auto Exited = FEXCore::Utils::PearFEXMemory::Exit(Facts);
    PEAR_FEX_REQUIRE_RESULT(!!Exited, "Pear dispatcher native return refused: status {}, domain {}, code {}", Exited);
#endif
  }

  void ExecuteJITCallback(FEXCore::Core::CpuStateFrame* Frame, uint64_t RIP) {
#ifdef PEAR_FEX_MEMORY_OWNER
    PEAR_FEX_REQUIRE(FEXCore::Utils::PearFEXMemory::Retirement::AdmissionOpen(), "Pear source retirement admission is closed");
    const auto Facts = GetPearSnapshot();
    const auto Base = reinterpret_cast<uintptr_t>(Facts.Base);
    const auto Address = reinterpret_cast<uintptr_t>(CallbackPtr);
    PEAR_FEX_REQUIRE(Facts && Facts.Token.expected_state == PEAR_FEX_PUBLISHED_RX &&
                      Facts.Token.allocation_class == PEAR_FEX_CLASS_DISPATCHER && Address >= Base &&
                      Address-Base < Facts.Token.extent_size && !(Address & 3), "Pear dispatcher entry range unavailable");
    const auto Entered = FEXCore::Utils::PearFEXMemory::Enter(Facts, Address-Base);
    PEAR_FEX_REQUIRE_RESULT(!!Entered, "Pear dispatcher entry refused: status {}, domain {}, code {}", Entered);
#endif
    CallbackPtr(Frame, RIP);
#ifdef PEAR_FEX_MEMORY_OWNER
    const auto Exited = FEXCore::Utils::PearFEXMemory::Exit(Facts);
    PEAR_FEX_REQUIRE_RESULT(!!Exited, "Pear dispatcher native return refused: status {}, domain {}, code {}", Exited);
#endif
  }
#endif

  uint64_t GetExitFunctionLinkerAddress() const {
    return ExitFunctionLinkerAddress;
  }

  SignalDelegatorConfig MakeSignalDelegatorConfig() const;

#ifdef PEAR_FEX_MEMORY_OWNER
  FEXCore::Utils::PearFEXMemory::Allocation GetPearSnapshot() const { return PearToken.Snapshot(); }
  // Private finite source fixture: caller supplies only its real Frame. The
  // native target is fixed by this translation unit; no guest callback input.
  FEXCore::Utils::PearFEXMemory::Result ExecutePearFiniteTransfer(FEXCore::Core::CpuStateFrame*);
  bool IsPearNativeResume(uintptr_t PC) const {
    return PC && (PC == PearCompileResumePC || PC == PearSingleStepResumePC || PC == PearExitLinkResumePC || PC == PearFiniteResumePC);
  }
#endif
protected:
  FEXCore::Context::ContextImpl* CTX;

  using AsmDispatch = void (*)(FEXCore::Core::CpuStateFrame* Frame, bool SingleInst);
  using JITCallback = void (*)(FEXCore::Core::CpuStateFrame* Frame, uint64_t RIP);

  AsmDispatch DispatchPtr {};
  JITCallback CallbackPtr {};
private:
#ifdef PEAR_FEX_MEMORY_OWNER
  FEXCore::Utils::PearFEXMemory::Result InitializePear();
  FEXCore::Utils::PearFEXMemory::TokenState PearToken {};
  uintptr_t PearCompileResumePC {};
  uintptr_t PearSingleStepResumePC {};
  uintptr_t PearExitLinkResumePC {};
  uintptr_t PearFiniteEntryPC {}, PearFiniteResumePC {};
#endif
  /**
   * @name Dispatch Helper functions
   * @{ */
  uint64_t ThreadStopHandlerAddress {};
  uint64_t ThreadStopHandlerAddressSpillSRA {};
  uint64_t AbsoluteLoopTopAddress {};
  uint64_t AbsoluteLoopTopAddressFillSRA {};
  uint64_t AbsoluteLoopTopAddressEnterEC {};
  uint64_t AbsoluteLoopTopAddressEnterECFillSRA {};
  uint64_t ThreadPauseHandlerAddress {};
  uint64_t ThreadPauseHandlerAddressSpillSRA {};
  uint64_t ThreadDispatchSyscallHandler {};
  uint64_t ThreadDispatchRemoveCodeEntry {};
  uint64_t ExitFunctionLinkerAddress {};
  uint64_t SignalHandlerReturnAddress {};
  uint64_t SignalHandlerReturnAddressRT {};
  uint64_t GuestSignal_SIGILL {};
  uint64_t GuestSignal_SIGTRAP {};
  uint64_t GuestSignal_SIGSEGV {};

  uint64_t PauseReturnInstruction {};
  std::array<uint64_t, FallbackABI::FABI_UNKNOWN> ABIPointers {};
  /**  @} */

  uint64_t Start {};
  uint64_t End {};

  // Long division helpers
  uint64_t LUDIVHandlerAddress {};
  uint64_t LDIVHandlerAddress {};

  // F64 reduced-precision shared handlers
  uint64_t F64SinHandlerAddress {};
  uint64_t F64CosHandlerAddress {};
  uint64_t F64TanHandlerAddress {};
  uint64_t F64F2XM1HandlerAddress {};
  uint64_t F64ScaleHandlerAddress {};
  uint64_t F64AtanHandlerAddress {};
  uint64_t F64FYL2XHandlerAddress {};
  uint64_t F64FYL2XP1HandlerAddress {};
  uint64_t F64FPREMHandlerAddress {};
  uint64_t F64FPREM1HandlerAddress {};

  void EmitDispatcher();
#ifdef PEAR_FEX_MEMORY_OWNER
  void RegisterDispatcherSymbols();
#endif
  uint64_t GenerateABICall(FallbackABI ABI);

  // Inline softfloat conversion emitters - avoid FPCR save/restore overhead
  // These emit ARM64 code that performs the conversion using only integer ops
  void EmitI16ToExtF80();
  void EmitI32ToExtF80();
  void EmitF32ToExtF80();
  void EmitF64ToExtF80();

  // Shared label set for the LUT-based F64 log2 path used by both FYL2X and
  // FYL2XP1. The pool is emitted once via EmitF64Log2Constants.
  struct F64Log2Constants {
    ARMEmitter::ForwardLabel One;
    ARMEmitter::ForwardLabel A0, A1, A2, A3, A4, A5, A6, A7;
    ARMEmitter::ForwardLabel Table;
  };

  void EmitF64Sin();
  void EmitF64Cos();
  void EmitF64Tan();
  void EmitF64F2XM1();
  void EmitF64Scale();
  void EmitF64Atan();
  void EmitF64FYL2X(F64Log2Constants& C);
  void EmitF64FYL2XP1(F64Log2Constants& C);
  void EmitF64Log2Constants(F64Log2Constants& C);
  void EmitF64FPREM();
  void EmitF64FPREM1();

  FEX_CONFIG_OPT(DisableL2Cache, DISABLEL2CACHE);
};

} // namespace FEXCore::CPU
