// SPDX-License-Identifier: MIT
#ifdef PEAR_FEX_MEMORY_OWNER
#include <FEXCore/Utils/PearDataMemory.h>
#endif
/*
$info$
glossary: Splatter ~ a code generator backend that concatenates configurable macros instead of doing isel
glossary: IR ~ Intermediate Representation, our high-level opcode representation, loosely modeling arm64
glossary: SSA ~ Single Static Assignment, a form of representing IR in memory
glossary: Basic Block ~ A block of instructions with no control flow, terminated by control flow
glossary: Fragment ~ A Collection of basic blocks, possibly an entire guest function or a subset of it
tags: backend|arm64
desc: Main glue logic of the arm64 splatter backend
$end_info$
*/

#include <FEXCore/Utils/PearSourceGuard.h>
#include "Interface/Context/Context.h"
#include "Interface/Core/LookupCache.h"
#ifdef PEAR_FEX_MEMORY_OWNER
#include "Interface/Core/PearJITLinks.h"
#endif
#include "Interface/Core/Dispatcher/Dispatcher.h"
#include "Interface/Core/Interpreter/InterpreterOps.h"
#include "Interface/Core/JIT/DebugData.h"
#include "Interface/Core/JIT/JITClass.h"
#include "Interface/IR/Passes/RegisterAllocationPass.h"

#include "Utils/MemberFunctionToPointer.h"
#include "Utils/variable_length_integer.h"

#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/Utils/EnumUtils.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/LongJump.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/Utils/Telemetry.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/HLE/SyscallHandler.h>

#include <cstdio>
#include <cstring>
#include <optional>
#include <type_traits>
#include <unistd.h>
#ifdef _WIN32
#include <atomic>
#else
#include <FEXHeaderUtils/Syscalls.h>
#endif

namespace {
struct DivRem {
  uint64_t Quotient;
  uint64_t Remainder;
};

static struct DivRem LUDIV(uint64_t SrcHigh, uint64_t SrcLow, uint64_t Divisor) {
  __uint128_t Source = (static_cast<__uint128_t>(SrcHigh) << 64) | SrcLow;

  return {
    .Quotient = (uint64_t)(Source / Divisor),
    .Remainder = (uint64_t)(Source % Divisor),
  };
}

static struct DivRem
LDIV(uint64_t SrcHigh, uint64_t SrcLow, int64_t Divisor) {
  __int128_t Source = (static_cast<__uint128_t>(SrcHigh) << 64) | SrcLow;

  return {
    .Quotient = (uint64_t)(Source / Divisor),
    .Remainder = (uint64_t)(Source % Divisor),
  };
}

#ifndef _WIN32

static std::optional<uint64_t>
RDRANDFallback(uint64_t Reseed) {
  uint64_t Value {};
  FHU::Syscalls::getrandom(&Value, sizeof(Value), 0);
  return Value;
}

#else

// Windows does not have an equivalent to getrandom() without dynamically linking
// bcrypt et al. Since this fallback is just for compat it does not need to be
// cryptographic, so instead we vendor SplitMix64 as a naive fallback.

// Reference implementation by Sebastiano Vigna, public domain (CC0)
// https://prng.di.unimi.it/splitmix64.c
static std::atomic<uint64_t>
  RNGState {static_cast<uint64_t>(__builtin_readcyclecounter())};

static std::optional<uint64_t> RDRANDFallback(uint64_t Reseed) {
  const uint64_t State = RNGState.load(std::memory_order_relaxed) + 0x9E3779B97F4A7C15ULL;
  RNGState.store(State, std::memory_order_relaxed);
  uint64_t Value = (State ^ (State >> 30)) * 0xBF58476D1CE4E5B9ULL;
  Value = (Value ^ (Value >> 27)) * 0x94D049BB133111EBULL;
  return Value ^ (Value >> 31);
}
#endif

static void PrintValue(uint64_t Value) {
  LogMan::Msg::DFmt("Value: 0x{:x}", Value);
}

static void PrintMsg(const char* Value) {
  LogMan::Msg::DFmt("{}", Value);
}

static void PrintVectorValue(uint64_t Value, uint64_t ValueUpper) {
  LogMan::Msg::DFmt("Value: 0x{:016x}'{:016x}", ValueUpper, Value);
}
} // namespace

namespace FEXCore::CPU {

void Arm64JITCore::Op_Unhandled(const IR::IROp_Header* IROp, IR::Ref Node) {
  FallbackInfo Info;
  if (!InterpreterOps::GetFallbackHandler(IROp, &Info)) {
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
    LOGMAN_MSG_A_FMT("Unhandled IR Op: {}", FEXCore::IR::GetName(IROp->Op));
#endif
  } else {
    auto FillF80x2Result = [&](auto DstLo, auto DstHi) {
      mov(DstLo.Q(), VTMP1.Q());
      mov(DstHi.Q(), VTMP2.Q());
    };

    auto FillF64x2Result = [&](auto DstLo, auto DstHi) {
      fmov(DstLo.D(), VTMP1.D());
      fmov(DstHi.D(), VTMP2.D());
    };

    auto FillF80Result = [&]() {
      const auto Dst = GetVReg(Node);
      mov(Dst.Q(), VTMP1.Q());
    };

    auto FillF64Result = [&]() {
      const auto Dst = GetVReg(Node);
      fmov(Dst.D(), VTMP1.D());
    };

    auto FillF32Result = [&]() {
      const auto Dst = GetVReg(Node);
      fmov(Dst.S(), VTMP1.S());
    };

    auto FillI64Result = [&]() {
      const auto Dst = GetReg(Node);
      mov(Dst.X(), TMP1);
    };

    auto FillI32Result = [&]() {
      const auto Dst = GetReg(Node);
      mov(Dst.W(), TMP1.W());
    };

    auto FillI16Result = [&]() {
      const auto Dst = GetReg(Node);
      mov(Dst.W(), TMP1.W());
    };

    switch (Info.ABI) {
    case FABI_F80_I16_F32_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): source
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      fmov(VTMP1.S(), Src1.S());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillF80Result();
    } break;

    case FABI_F80_I16_F64_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): source
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      fmov(VTMP1.D(), Src1.D());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillF80Result();
    } break;

    case FABI_F80_I16_I16_PTR:
    case FABI_F80_I16_I32_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // tmp2 (x1/x11): source
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetReg(IROp->Args[0]);

      // Need to sign or zero extend this for the dispatcher handler.
      if (Info.ABI == FABI_F80_I16_I16_PTR) {
        sxth(ARMEmitter::Size::i32Bit, TMP2, Src1);
      } else {
        mov(ARMEmitter::Size::i32Bit, TMP2, Src1);
      }

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillF80Result();
    } break;

    case FABI_F32_I16_F80_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): source
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      mov(VTMP1.Q(), Src1.Q());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillF32Result();
    } break;

    case FABI_F64_I16_F80_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): source
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      mov(VTMP1.Q(), Src1.Q());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillF64Result();
    } break;

    case FABI_F64_F64_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): vector source
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      fmov(VTMP1.D(), Src1.D());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillF64Result();
    } break;
    case FABI_F64x2_F64_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): vector source
      // vtmp2 (v1/v16): vector source
#ifdef VIXL_SIMULATOR
      LOGMAN_THROW_A_FMT(CTX->Config.DisableVixlIndirectCalls, "Vector register pairs unsupported by simulator currently");
#endif
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      const auto DstLo = GetVReg(IROp->Args[1]);
      const auto DstHi = GetVReg(IROp->Args[2]);

      fmov(VTMP1.D(), Src1.D());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillF64x2Result(DstLo, DstHi);
    } break;

    case FABI_F64_F64_F64_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): vector source 1
      // vtmp2 (v1/v17): vector source 2
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      const auto Src2 = GetVReg(IROp->Args[1]);

      fmov(VTMP1.D(), Src1.D());
      fmov(VTMP2.D(), Src2.D());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillF64Result();
    } break;

    case FABI_I16_I16_F80_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): source
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      mov(VTMP1.Q(), Src1.Q());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillI16Result();
    } break;

    case FABI_I32_I16_F80_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): source
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      mov(VTMP1.Q(), Src1.Q());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillI32Result();
    } break;

    case FABI_I64_I16_F80_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): source
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      mov(VTMP1.Q(), Src1.Q());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillI64Result();
    } break;

    case FABI_I64_I16_F80_F80_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): vector source 1
      // vtmp2 (v1/v17): vector source 2
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      const auto Src2 = GetVReg(IROp->Args[1]);
      mov(VTMP1.Q(), Src1.Q());
      mov(VTMP2.Q(), Src2.Q());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillI64Result();
    } break;

    case FABI_F80_I16_F80_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): vector source 1
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      mov(VTMP1.Q(), Src1.Q());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillF80Result();
    } break;

    case FABI_F80x2_I16_F80_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): vector source 1
      // vtmp2 (v1/v16): vector source 2
#ifdef VIXL_SIMULATOR
      LOGMAN_THROW_A_FMT(CTX->Config.DisableVixlIndirectCalls, "Vector register pairs unsupported by simulator currently");
#endif
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      const auto DstLo = GetVReg(IROp->Args[1]);
      const auto DstHi = GetVReg(IROp->Args[2]);

      mov(VTMP1.Q(), Src1.Q());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillF80x2Result(DstLo, DstHi);
    } break;

    case FABI_F80_I16_F80_F80_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): vector source 1
      // vtmp2 (v1/v17): vector source 2
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      const auto Src2 = GetVReg(IROp->Args[1]);

      mov(VTMP1.Q(), Src1.Q());
      mov(VTMP2.Q(), Src2.Q());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillF80Result();
    } break;

    case FABI_I32_I64_I64_V128_V128_I16: {
      // Linux Reg/Win32 Reg:
      // stack: FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): vector source 1
      // vtmp2 (v1/v17): vector source 2
      // tmp1 (x0/x10): source 1
      // tmp2 (x1/x11): source 2
      // tmp3 (x2/x12): source 3
      const auto Op = IROp->C<IR::IROp_VPCMPESTRX>();
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));

      stp<ARMEmitter::IndexType::PRE>(TMP1, ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto SrcRAX = GetReg(Op->RAX);
      const auto SrcRDX = GetReg(Op->RDX);
      const auto Control = Op->Control;

      mov(TMP1, SrcRAX.X());
      mov(TMP2, SrcRDX.X());
      movz(ARMEmitter::Size::i32Bit, TMP3, Control);

      const auto Src1 = GetVReg(Op->LHS);
      const auto Src2 = GetVReg(Op->RHS);

      mov(VTMP1.Q(), Src1.Q());
      mov(VTMP2.Q(), Src2.Q());

      blr(TMP4);

      ldp<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::zr, ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillI32Result();
    } break;
    case FABI_I32_V128_V128_I16: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): vector source 1
      // vtmp2 (v1/v17): vector source 2
      // tmp1 (x0/x10): source 1
      const auto Op = IROp->C<IR::IROp_VPCMPISTRX>();
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(Op->LHS);
      const auto Src2 = GetVReg(Op->RHS);
      const auto Control = Op->Control;

      mov(VTMP1.Q(), Src1.Q());
      mov(VTMP2.Q(), Src2.Q());
      movz(ARMEmitter::Size::i32Bit, TMP1, Control);

      ldr(TMP2, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP2);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillI32Result();
    } break;
    case FABI_UNKNOWN:
    default:
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
      LOGMAN_MSG_A_FMT("Unhandled IR Fallback ABI: {} {}", FEXCore::IR::GetName(IROp->Op), ToUnderlying(Info.ABI));
#endif
      break;
    }
  }
}

#ifndef PEAR_FEX_MEMORY_OWNER
static void DirectBlockDelinker(FEXCore::Context::ExitFunctionLinkData* Record, bool Call) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // An under-lookup-lock callback cannot start a quiescent owner transaction.
  LOGMAN_THROW_A_FMT(false, "Pear direct delink requires a source pre-lock patch transaction");
  return;
#endif
  uintptr_t JumpThunkStartAddress = reinterpret_cast<uintptr_t>(Record) - 0x10;
  uintptr_t CallerAddress = JumpThunkStartAddress + Record->CallerOffset;
  auto BranchOffset = JumpThunkStartAddress / 4 - CallerAddress / 4;

  // Replace the patched callsite with a branch to the jump thunk.
  uint32_t BranchInst = 0;
  ARMEmitter::Emitter BranchEmit(reinterpret_cast<uint8_t*>(&BranchInst), 4);
  if (Call) {
    BranchEmit.bl(BranchOffset);
  } else {
    BranchEmit.b(BranchOffset);
  }

  std::atomic_ref<uint32_t>(*reinterpret_cast<uint32_t*>(CallerAddress)).store(BranchInst, std::memory_order::relaxed);
  ARMEmitter::Emitter::ClearICache(reinterpret_cast<void*>(CallerAddress), 4);
}

static void IndirectBlockDelinker(FEXCore::Context::ExitFunctionLinkData* Record) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // An under-lookup-lock callback cannot start a quiescent owner transaction.
  LOGMAN_THROW_A_FMT(false, "Pear indirect delink requires a source pre-lock patch transaction");
  return;
#endif
  uintptr_t JumpThunkStartAddress = reinterpret_cast<uintptr_t>(Record) - 0x10;
  uint32_t BranchInst = 0;
  ARMEmitter::Emitter BranchEmit(reinterpret_cast<uint8_t*>(&BranchInst), 4);
  // Restore branch +2 instructions to jump to the linker block
  BranchEmit.b(0x2);

  std::atomic_ref<uint32_t>(*reinterpret_cast<uint32_t*>(JumpThunkStartAddress)).store(BranchInst, std::memory_order::relaxed);
  ARMEmitter::Emitter::ClearICache(reinterpret_cast<void*>(JumpThunkStartAddress), 4);

  // No need to reset HostCode here as the exit linker pointer is stored separately, and if the block is relinked it will be updated.
}

uint64_t Arm64JITCore::ExitFunctionLink(FEXCore::Core::CpuStateFrame* Frame, FEXCore::Context::ExitFunctionLinkData* Record) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Do not read an RX record after native handoff or patch beneath lookup locks.
  // The original IsInt26 direct/indirect algorithms remain intact below; the
  // exact active-lease snapshot plus pre-lock write transaction is unresolved.
  LOGMAN_THROW_A_FMT(false, "Pear exit-link source snapshot/patch transaction is unavailable");
  return 0;
#endif
  auto Thread = Frame->Thread;
  bool TFSet = Thread->CurrentFrame->State.flags[X86State::RFLAG_TF_RAW_LOC];
  uintptr_t HostCode {};
  auto GuestRip = Record->GuestRIP;

  if (TFSet) {
    // If TF is set, the cache must be skipped as different code needs to be generated.
    Frame->State.rip = GuestRip;
    return Frame->Pointers.DispatcherLoopTop;
  } else {
    {
      // Guard the LookupCache lock with the code invalidation mutex, to avoid issues with forking
      auto lk_inval =
        GuardSignalDeferringSection<std::shared_lock>(static_cast<Context::ContextImpl*>(Thread->CTX)->CodeInvalidationMutex, Thread);
      HostCode = Thread->LookupCache->FindBlock(Thread, GuestRip);
    }
    if (!HostCode) {
      // Hold a reference to the code buffer, to avoid linking unmapped code if compilation triggers a recreation.
      auto CodeBuffer = static_cast<Arm64JITCore*>(Thread->CPUBackend.get())->CurrentCodeBuffer;
      HostCode = static_cast<Context::ContextImpl*>(Thread->CTX)->CompileBlock(Frame, GuestRip, 0);
      if (Thread->LookupCache->Shared != CodeBuffer->LookupCache.get()) {
        return HostCode;
      }
    }
  }

  // See ExitFunction in BranchOps.cpp for an assembly level view of the handled cases.
  uintptr_t JumpThunkStartAddress = reinterpret_cast<uintptr_t>(Record) - 0x10;
  uintptr_t CallerAddress = JumpThunkStartAddress + Record->CallerOffset;
  auto BranchOffset = HostCode / 4 - CallerAddress / 4;

  uint32_t ExpectedKnownCallMarkerInst = 0;
  ARMEmitter::Emitter ExpectedKnownCallMarkerEmit(reinterpret_cast<uint8_t*>(&ExpectedKnownCallMarkerInst), 4);
  ExpectedKnownCallMarkerEmit.adr(TMP1, 0xC);

  // Guard the LookupCache lock with the code invalidation mutex, to avoid issues with forking
  auto lk_inval = GuardSignalDeferringSection<std::shared_lock>(static_cast<Context::ContextImpl*>(Thread->CTX)->CodeInvalidationMutex, Thread);

  // Lock here is necessary to prevent simultaneous linking and delinking
  auto lk = Thread->LookupCache->AcquireWriteLock();

  // For non-calls, this would extend into the block's code, however that's fine as an out-of-range adr would never
  // be generated avoiding any false positives.
  uintptr_t KnownCallMarkerAddr = CallerAddress - 0x8;
  uint32_t KnownCallMarkerInst = *reinterpret_cast<uint32_t*>(KnownCallMarkerAddr);
  if (ARMEmitter::Emitter::IsInt26(BranchOffset)) {
    // Directly patch the callsite with the appropriate branch instruction.
    uint32_t BranchInst = 0;
    ARMEmitter::Emitter BranchEmit(reinterpret_cast<uint8_t*>(&BranchInst), 4);

    if (KnownCallMarkerInst == ExpectedKnownCallMarkerInst) {
      BranchEmit.bl(BranchOffset);
      Thread->LookupCache->AddBlockLink(
        GuestRip, Record, [](FEXCore::Context::ExitFunctionLinkData* Record) { DirectBlockDelinker(Record, true); }, lk);
    } else {
      BranchEmit.b(BranchOffset);
      Thread->LookupCache->AddBlockLink(
        GuestRip, Record, [](FEXCore::Context::ExitFunctionLinkData* Record) { DirectBlockDelinker(Record, false); }, lk);
    }

    std::atomic_ref<uint32_t>(*reinterpret_cast<uint32_t*>(CallerAddress)).store(BranchInst, std::memory_order::relaxed);
    ARMEmitter::Emitter::ClearICache(reinterpret_cast<void*>(CallerAddress), 4);
  } else {
    // This case is common between calls and jumps as the thunk callsite can be left untouched.
    std::atomic_ref<uint64_t>(Record->HostCode).store(HostCode, std::memory_order::seq_cst);
#ifdef ARCHITECTURE_arm64
    // Make memory write visible to other threads reading the same location
    asm volatile("dc cvau, %0; dsb ish" : : "r"(Record->HostCode) :);
#endif

    uint32_t LdrInst = 0;
    ARMEmitter::Emitter LdrEmit(reinterpret_cast<uint8_t*>(&LdrInst), 4);
    LdrEmit.ldr(TMP1, reinterpret_cast<uint64_t>(&Record->HostCode) - JumpThunkStartAddress);
    std::atomic_ref<uint32_t>(*reinterpret_cast<uint32_t*>(JumpThunkStartAddress)).store(LdrInst, std::memory_order::relaxed);
    ARMEmitter::Emitter::ClearICache(reinterpret_cast<void*>(JumpThunkStartAddress), 4);

    Thread->LookupCache->AddBlockLink(GuestRip, Record, IndirectBlockDelinker, lk);
  }

  return HostCode;
}

#else
extern "C" void PearLinkObservation(uint32_t, uint32_t, uint64_t, uint64_t);
uint64_t Arm64JITCore::ExitPearFunctionLink(FEXCore::Core::CpuStateFrame* Frame,
    FEXCore::Context::ExitFunctionLinkData* Record, uintptr_t ResumePC) {
  namespace Memory=FEXCore::Utils::PearFEXMemory;
  auto Life=Memory::AcquireCurrentSourceLifetime();
  auto* Thread=Life ? Life.ActualThread() : nullptr;
  auto* C=Life ? const_cast<FEXCore::Context::ContextImpl*>(
      static_cast<const FEXCore::Context::ContextImpl*>(Life.ActualContext())) : nullptr;
  PEAR_FEX_REQUIRE(Thread && C && Life.Validate() && Frame==Thread->CurrentFrame &&
    Frame->Thread==Thread && Thread->CTX==C && Thread->CPUBackend && C->Dispatcher,
    "Pear linker actual source lifetime unavailable");
  const auto Bound=Memory::BindSourceThread(Thread);
  PEAR_FEX_REQUIRE_RESULT(!!Bound, "Pear linker source binding refused: status {}, domain {}, code {}", Bound);
  const auto Protection=C->Dispatcher->GetPearSnapshot();
  const auto Window=Thread->CPUBackend->FindPearManagedWindow(reinterpret_cast<uintptr_t>(Record));
  const auto Retained=Thread->CPUBackend->FindPearRetainedTarget(reinterpret_cast<uintptr_t>(Record));
  PEAR_FEX_REQUIRE(Window && Retained && Memory::HasManagedActive(Protection),
                    "Pear linker record is not an actual retained source target under D");
  FEXCore::Context::ExitFunctionLinkData Copy {};
  PearJITLinkLayout::Layout Layout {};
  std::array<uint8_t,PearJITLinkLayout::THUNK_BYTES> Thunk {};
  std::array<uint8_t,PearJITLinkLayout::CALLER_BYTES> Caller {};
  uintptr_t Host {};
  uint64_t Revision {};
  {
    auto Invalidation=GuardSignalDeferringSection<std::shared_lock>(C->CodeInvalidationMutex,Thread);
    Revision=C->GetPearInvalidationRevision();
    std::span<uint8_t> RecordBytes {reinterpret_cast<uint8_t*>(&Copy),sizeof(Copy)};
    const auto Read=Memory::CopyManagedRXUnderGlobalLease(Protection,*Retained,Thread,Window->Offset,RecordBytes);
    PEAR_FEX_REQUIRE_RESULT(!!Read, "Pear linker record snapshot refused: status {}, domain {}, code {}", Read.Outcome);
    PEAR_FEX_REQUIRE(PearJITLinkLayout::Build(Window->Begin,Window->Size,reinterpret_cast<uintptr_t>(Record),Copy,Layout) &&
      (C->Config.Is64BitMode() || !(Copy.GuestRIP>>32)),"Pear linker source layout refused");
    const auto ReadThunk=Memory::CopyManagedRXUnderGlobalLease(Protection,*Retained,Thread,Layout.ThunkOffset,Thunk);
    const auto ReadCaller=Memory::CopyManagedRXUnderGlobalLease(Protection,*Retained,Thread,Layout.MarkerOffset,Caller);
    PEAR_FEX_REQUIRE(!!ReadThunk && !!ReadCaller &&
      !std::memcmp(Thunk.data()+16,&Copy,sizeof(Copy)),"Pear linker source bytes changed during active snapshot");
    Host=Thread->LookupCache->FindBlock(Thread,Copy.GuestRIP);
  }
  if (Frame->State.flags[X86State::RFLAG_TF_RAW_LOC]) {
    Frame->State.rip=Copy.GuestRIP;
    return Frame->Pointers.DispatcherLoopTop;
  }
  // Every byte required from Record/caller/thunk is now in bounded NX storage.
  // This generated D resume label is exact; a synthetic Frame is never used.
  FEXCore::Context::ContextImpl::PearDispatcherGate Gate {};
  const auto Handed=C->BeginPearDispatcherGate(Frame,ResumePC,Gate);
  PEAR_FEX_REQUIRE_RESULT(!!Handed, "Pear linker native handoff refused: status {}, domain {}, code {}", Handed);
  Memory::SourceMutationTurn Mutation {Life};
  const auto Turn=Mutation.Status();
  PEAR_FEX_REQUIRE_RESULT(!!Turn, "Pear linker mutation turn refused: status {}, domain {}, code {}",Turn);
  const bool Changed=Revision!=C->GetPearInvalidationRevision();
  if (Changed) Host=0; // Never reuse the lookup captured before a peer invalidation.
  const bool HadHost=Host!=0;
  if (!Host) Host=C->CompilePearBlock(Frame,Copy.GuestRIP,0);
  PEAR_FEX_REQUIRE(Host && !(Host&3),"Pear linker compiled no admitted target");
  // Upstream permits replacement of a shared mapping when a backend switches
  // buffers. A thread-local L1 hit can still name the retained older block.
  // The source mutation turn excludes peer publication here; bind new links
  // to the authoritative shared mapping under its existing read lock.
  {
    auto Invalidation=GuardSignalDeferringSection<std::shared_lock>(C->CodeInvalidationMutex,Thread);
    auto* Shared=Thread->LookupCache->Shared;
    auto Lookup=Shared->AcquireReadLock();
    if (const auto* Current=Shared->FindBlock(Copy.GuestRIP,Lookup)) Host=Current->HostCode;
  }
  auto TargetWindow=Thread->CPUBackend->FindPearManagedWindow(Host);
  const bool SameMap=TargetWindow && TargetWindow->Owner==Window->Owner &&
    Thread->LookupCache->Shared==Window->Owner->LookupCache.get();
  // Contended() only reports waiting inside turn acquisition. A peer may have
  // published after the RX snapshot but before this thread tried the turn.
  // In that case leave the existing indirect path intact, without minting a
  // transaction from stale caller/thunk bytes. Own compilation may also advance
  // this epoch; skipping this optional link remains safe in that case.
  const bool SameSourceEpoch=Window->Facts.Token.write_epoch==Window->Owner->GetPearSnapshot().Token.write_epoch;
  const bool Contended=Mutation.Contended();
  uint32_t LinkFacts=(SameMap?1U:0U)|(Changed?2U:0U)|(Contended?4U:0U)|(SameSourceEpoch?8U:0U)|(HadHost?16U:0U);
  if (SameMap && !Changed && !Mutation.Contended() && SameSourceEpoch) {
    uint32_t Marker {}; std::memcpy(&Marker,Caller.data(),sizeof(Marker));
    const auto Encoded=PearJITLinkLayout::Encode(Window->Begin,Layout,Host,Marker);
    PEAR_FEX_REQUIRE(PearJITLinkLayout::UnlinkedSourceMatches(Window->Begin,Layout,Encoded,Thunk,Caller),
                      "Pear linker bytes are not the actual appended pending-thunk/source caller shape");
    const auto Facts=Window->Owner->GetPearSnapshot();
    LinkFacts|=32U;
    const auto Ticket=PearJITLinks::Prepare(PearJITLinks::SourceDescriptor {Window->Owner,C,Facts,Layout,Encoded,
                                                                                     Thunk,Caller,Copy.GuestRIP,Host});
    if (Ticket) {
    LinkFacts|=64U;
    // Compile may append into A, but any real guest invalidation since the
    // original snapshot invalidates this source transaction before any store.
    const auto Patched=PearJITLinks::PatchPrepared(*Ticket,Thread,Revision);
    PEAR_FEX_REQUIRE_RESULT(!!Patched, "Pear link patch refused: status {}, domain {}, code {}", Patched);
    {
      auto Invalidation=GuardSignalDeferringSection<std::shared_lock>(C->CodeInvalidationMutex,Thread);
      auto Lookup=Thread->LookupCache->AcquireWriteLock();
      PEAR_FEX_REQUIRE(C->GetPearInvalidationRevision()==Revision && Thread->LookupCache->Shared==Window->Owner->LookupCache.get(),
                        "Pear linked source changed before lookup visibility");
      Thread->LookupCache->AddPearBlockLink(Copy.GuestRIP,Record,*Ticket,Lookup);
      const auto Committed=PearJITLinks::Commit(*Ticket);
      PEAR_FEX_REQUIRE_RESULT(!!Committed, "Pear source link ticket publication refused: status {}, domain {}, code {}", Committed);
    }
    } else {
      const auto Healthy=Memory::Links::FirstFailureSnapshot();
      PEAR_FEX_REQUIRE(!!Healthy && Memory::Links::EntryAdmissionOpen(),
                       "Pear source link admission closed, not an optional capacity/entry-seal miss");
    }
  }
  Mutation.Release();
  const auto Resumed=C->FinishPearDispatcherGate(Gate);
  PEAR_FEX_REQUIRE_RESULT(!!Resumed, "Pear linker native resume refused: status {}, domain {}, code {}", Resumed);
  // The source target is revalidated under renewed genuine D protection before
  // its actual address is returned to the generated br instruction.
  TargetWindow=Thread->CPUBackend->FindPearManagedWindow(Host);
  const auto Target=Thread->CPUBackend->FindPearRetainedTarget(Host);
  std::array<uint8_t,4> TargetWord {};
  PEAR_FEX_REQUIRE(TargetWindow && Target,"Pear linked target reference is unavailable after native resume");
  const auto Observed=Memory::CopyManagedRXUnderGlobalLease(C->Dispatcher->GetPearSnapshot(),*Target,Thread,
                                                          TargetWindow->Offset,TargetWord);
  PEAR_FEX_REQUIRE_RESULT(!!Observed, "Pear linked target RX observation refused: status {}, domain {}, code {}", Observed.Outcome);
  PearLinkObservation(1,LinkFacts,Copy.GuestRIP,reinterpret_cast<uintptr_t>(Record));
  return Host;
}
#endif

#ifdef PEAR_FEX_MEMORY_OWNER
extern "C" uint32_t PearFiniteCheckpoint;
FEXCore::Utils::PearFEXMemory::Result Arm64JITCore::ExecutePearFiniteLinks(
    FEXCore::Core::CpuStateFrame* Frame, uintptr_t ResumePC) {
  namespace M=FEXCore::Utils::PearFEXMemory;
  auto Life=M::AcquireCurrentSourceLifetime();
  auto* Thread=Life ? Life.ActualThread() : nullptr;
  auto* C=Life ? const_cast<FEXCore::Context::ContextImpl*>(
    static_cast<const FEXCore::Context::ContextImpl*>(Life.ActualContext())) : nullptr;
  if (!Thread || !C || Frame!=Thread->CurrentFrame || Frame->Thread!=Thread || !C->Dispatcher ||
      !Thread->CPUBackend || !Thread->LookupCache || !M::HasManagedActive(C->Dispatcher->GetPearSnapshot()))
    return {PEAR_FEX_UNAVAILABLE,0,0};
  for (uint32_t I=0;I<6;++I) {
    PearFiniteCheckpoint=64+I*16;
    auto Window=Thread->CPUBackend->FindPearManagedWindow(Frame->State.InlineJITBlockHeader);
    if (!Window || Thread->LookupCache->Shared!=Window->Owner->LookupCache.get()) return {PEAR_FEX_UNAVAILABLE,0,0};
    const size_t RecordOffset=528+128*I;
    auto* Record=reinterpret_cast<FEXCore::Context::ExitFunctionLinkData*>(Window->Begin+RecordOffset);
    auto Target=Thread->CPUBackend->FindPearRetainedTarget(reinterpret_cast<uintptr_t>(Record));
    if (!Target) return {PEAR_FEX_UNAVAILABLE,0,0};
    const auto Protection=C->Dispatcher->GetPearSnapshot();
    FEXCore::Context::ExitFunctionLinkData Copy {};
    auto Read=M::CopyManagedRXUnderGlobalLease(Protection,*Target,Thread,RecordOffset,
      {reinterpret_cast<uint8_t*>(&Copy),sizeof(Copy)});
    if (!Read) return Read.Outcome;
    PearJITLinkLayout::Layout Layout;
    std::array<uint8_t,PearJITLinkLayout::THUNK_BYTES> Thunk {};
    std::array<uint8_t,PearJITLinkLayout::CALLER_BYTES> Caller {};
    if (Copy.GuestRIP!=0x2000+4*I || !PearJITLinkLayout::Build(Window->Begin,Window->Size,
        reinterpret_cast<uintptr_t>(Record),Copy,Layout)) return {PEAR_FEX_INVALID_REQUEST,0,0};
    Read=M::CopyManagedRXUnderGlobalLease(Protection,*Target,Thread,Layout.ThunkOffset,Thunk);
    if (!Read) return Read.Outcome;
    Read=M::CopyManagedRXUnderGlobalLease(Protection,*Target,Thread,Layout.MarkerOffset,Caller);
    if (!Read) return Read.Outcome;
    uint32_t Marker {};std::memcpy(&Marker,Caller.data(),4);
    const auto Encoded=PearJITLinkLayout::Encode(Window->Begin,Layout,Window->Begin,Marker);
    if (!Encoded.Direct || Encoded.Call!=((I&1)!=0) ||
        !PearJITLinkLayout::UnlinkedSourceMatches(Window->Begin,Layout,Encoded,Thunk,Caller))
      return {PEAR_FEX_INVALID_REQUEST,0,0};
    // Reuse the genuine source map and node allocator. No guest cache or code
    // is executed; this original finite target is already owned and published.
    {
      auto Lock=Thread->LookupCache->AcquireWriteLock();
      auto* Map=Thread->LookupCache->Shared;
      if (!Map->BlockList.empty() || !Map->BlockLinks->empty()) return {PEAR_FEX_UNAVAILABLE,0,0};
      Map->AddBlockMapping(Copy.GuestRIP,{},reinterpret_cast<void*>(Window->Begin),Lock);
      if (I>=4) {
        const std::array<uint64_t,1> Addresses{Copy.GuestRIP};
        if (!Map->AddBlockExecutableRange(Addresses,Copy.GuestRIP,4,Lock)) return {PEAR_FEX_STALE_IDENTITY,0,0};
      }
    }
    FEXCore::Context::ContextImpl::PearDispatcherGate Gate {};
    auto Outcome=C->BeginPearDispatcherGate(Frame,ResumePC,Gate);
    if (!Outcome) return Outcome;
    PearFiniteCheckpoint=65+I*16;
    const auto Revision=C->GetPearInvalidationRevision();
    const auto Facts=Window->Owner->GetPearSnapshot();
    // A real prepared ticket closes entry; cancellation releases it without
    // touching managed bytes or leaving a stale strong source reference.
    const auto Cancelled=PearJITLinks::Prepare(PearJITLinks::SourceDescriptor{Window->Owner,C,Facts,Layout,Encoded,
      Thunk,Caller,Copy.GuestRIP,Window->Begin});
    if (!Cancelled) return {PEAR_FEX_UNAVAILABLE,0,0};
    M::Links::SealedEntry RefusedEntry;
    const auto EntryResult=M::Links::TrySealEntry(Life,RefusedEntry);
    if (EntryResult.Status!=PEAR_FEX_UNAVAILABLE || EntryResult.ErrorDomain || EntryResult.ErrorCode)
      return {PEAR_FEX_STALE_IDENTITY,0,0};
    Outcome=PearJITLinks::CancelPrepared(*Cancelled);if (!Outcome) return Outcome;
    if (M::Links::HasOutstanding(C)) return {PEAR_FEX_STALE_IDENTITY,0,0};
    const auto Ticket=PearJITLinks::Prepare(PearJITLinks::SourceDescriptor{Window->Owner,C,Facts,Layout,Encoded,
      Thunk,Caller,Copy.GuestRIP,Window->Begin});
    if (!Ticket) return {PEAR_FEX_UNAVAILABLE,0,0};
    Outcome=PearJITLinks::PatchPrepared(*Ticket,Thread,Revision);if (!Outcome) return Outcome;
    {
      auto Lock=Thread->LookupCache->AcquireWriteLock();
      Thread->LookupCache->AddPearBlockLink(Copy.GuestRIP,Record,*Ticket,Lock);
      Outcome=PearJITLinks::Commit(*Ticket);
    }
    if (!Outcome) return Outcome;
    Outcome=C->FinishPearDispatcherGate(Gate);if (!Outcome) return Outcome;
    PearFiniteCheckpoint=66+I*16;
    auto Fresh=Thread->CPUBackend->FindPearRetainedTarget(reinterpret_cast<uintptr_t>(Record));
    if (!Fresh) return {PEAR_FEX_UNAVAILABLE,0,0};
    uint32_t Word {};
    Read=M::CopyManagedRXUnderGlobalLease(C->Dispatcher->GetPearSnapshot(),*Fresh,Thread,Layout.CallerOffset,
      {reinterpret_cast<uint8_t*>(&Word),sizeof(Word)});
    if (!Read) return Read.Outcome;
    if (Word!=Encoded.PatchedWord) return {PEAR_FEX_STALE_IDENTITY,0,0};
    FEXCore::Context::ContextImpl::PearDispatcherGate DelinkGate {};
    Outcome=C->BeginPearDispatcherGate(Frame,ResumePC,DelinkGate);if (!Outcome) return Outcome;
    Outcome=C->BeginPearLinkInvalidation(Thread);if (!Outcome) return Outcome;
    PearFiniteCheckpoint=67+I*16;
    if (I>=4) {
      const auto BeforeRevision=C->GetPearInvalidationRevision();
      {
        auto Invalidation=GuardSignalDeferringSection<std::unique_lock>(C->CodeInvalidationMutex,Thread);
        C->InvalidateCodeBuffersCodeRange(Copy.GuestRIP,4);
      }
      if (C->GetPearInvalidationRevision()!=BeforeRevision+1 ||
          !Thread->LookupCache->Shared->CodePages.empty() ||
          !Thread->LookupCache->Shared->BlockList.empty() || !Thread->LookupCache->Shared->BlockLinks->empty())
        return {PEAR_FEX_STALE_IDENTITY,0,0};
    } else {
      auto Lock=Thread->LookupCache->AcquireWriteLock();
      if (I<2) {
        if (!Thread->LookupCache->Shared->Erase(Copy.GuestRIP,Lock)) return {PEAR_FEX_STALE_IDENTITY,0,0};
      } else {
        Thread->LookupCache->Shared->ClearCache(Lock);
        if (!Thread->LookupCache->Shared->BlockList.empty() || !Thread->LookupCache->Shared->BlockLinks->empty())
          return {PEAR_FEX_STALE_IDENTITY,0,0};
      }
    }
    Outcome=C->FinishPearLinkInvalidation(Thread);if (!Outcome) return Outcome;
    Outcome=C->FinishPearDispatcherGate(DelinkGate);if (!Outcome) return Outcome;
    auto Final=Thread->CPUBackend->FindPearRetainedTarget(reinterpret_cast<uintptr_t>(Record));
    if (!Final) return {PEAR_FEX_UNAVAILABLE,0,0};
    std::array<uint8_t,PearJITLinkLayout::CALLER_BYTES> Restored {};
    Read=M::CopyManagedRXUnderGlobalLease(C->Dispatcher->GetPearSnapshot(),*Final,Thread,Layout.MarkerOffset,Restored);
    if (!Read) return Read.Outcome;
    if (Restored!=Caller || M::Links::HasOutstanding(C)) return {PEAR_FEX_STALE_IDENTITY,0,0};
    PearFiniteCheckpoint=68+I*16;
  }
  return {PEAR_FEX_OK,0,0};
}
#endif

#ifdef PEAR_FEX_MEMORY_OWNER
FEXCore::Utils::PearFEXMemory::Result Arm64JITCore::ExecutePearFinitePublication(
    FEXCore::Core::CpuStateFrame* Frame, uintptr_t ResumePC) {
  namespace M=FEXCore::Utils::PearFEXMemory;
  auto Life=M::AcquireCurrentSourceLifetime();
  auto* Thread=Life ? Life.ActualThread() : nullptr;
  auto* C=Life ? const_cast<FEXCore::Context::ContextImpl*>(
    static_cast<const FEXCore::Context::ContextImpl*>(Life.ActualContext())) : nullptr;
  if (!Thread || !C || Frame!=Thread->CurrentFrame || Frame->Thread!=Thread || !Thread->CPUBackend ||
      !C->Dispatcher || !M::HasManagedActive(C->Dispatcher->GetPearSnapshot())) return {PEAR_FEX_UNAVAILABLE,0,0};
  auto* JIT=static_cast<Arm64JITCore*>(Thread->CPUBackend.get());
  if (JIT->ThreadState!=Thread || JIT->PearPendingTemp || JIT->PearWriter || JIT->PearLabelFailure ||
      !JIT->CurrentCodeBuffer || Thread->LookupCache->Shared!=JIT->CurrentCodeBuffer->LookupCache.get())
    return {PEAR_FEX_UNAVAILABLE,0,0};
  for (uint32_t I=0;I<2;++I) {
    PearFiniteCheckpoint=384+I;
    FEXCore::Context::ContextImpl::PearDispatcherGate Gate {};
    auto Outcome=C->BeginPearDispatcherGate(Frame,ResumePC,Gate);if (!Outcome) return Outcome;
    PearFiniteCheckpoint=0x181;
    const auto Private=JIT->TempCodeBufferAllocator.ReownOrClaimBufferWithSize(8192);
    PearFiniteCheckpoint=0x182;
    if (!Private.Ptr || Private.Size!=8192) return {PEAR_FEX_UNAVAILABLE,0,0};
    MEMORY_BASIC_INFORMATION DataInfo {},GuardInfo {};
    PearFiniteCheckpoint=387;
    if (::VirtualQuery(Private.Ptr,&DataInfo,sizeof(DataInfo))!=sizeof(DataInfo)) return {PEAR_FEX_UNAVAILABLE,0,0};
    PearFiniteCheckpoint=388;
    if (::VirtualQuery(Private.Ptr+4096,&GuardInfo,sizeof(GuardInfo))!=sizeof(GuardInfo)) return {PEAR_FEX_UNAVAILABLE,0,0};
    PearFiniteCheckpoint=389;
    if (DataInfo.AllocationBase!=Private.Ptr || DataInfo.BaseAddress!=Private.Ptr) return {PEAR_FEX_UNAVAILABLE,0,0};
    PearFiniteCheckpoint=390;
    if (GuardInfo.AllocationBase!=Private.Ptr || GuardInfo.BaseAddress!=Private.Ptr+4096) return {PEAR_FEX_UNAVAILABLE,0,0};
    PearFiniteCheckpoint=391;
    if (DataInfo.State!=MEM_COMMIT || GuardInfo.State!=MEM_COMMIT) return {PEAR_FEX_UNAVAILABLE,0,0};
    PearFiniteCheckpoint=392;
    if (DataInfo.RegionSize<4096 || GuardInfo.RegionSize<4096) return {PEAR_FEX_UNAVAILABLE,0,0};
    PearFiniteCheckpoint=393;
    if ((DataInfo.Protect&0xff)!=PAGE_READWRITE) return {PEAR_FEX_UNAVAILABLE,0,0};
    PearFiniteCheckpoint=394;
    if ((GuardInfo.Protect&0xff)!=PAGE_NOACCESS) return {PEAR_FEX_UNAVAILABLE,0,0};
    // Original ARM64 LDR-literal/RET plus one inline constant. No guest input,
    // guest decoding, IR emission, JIT header or lookup publication is supplied.
    const uint32_t Instructions[]={0x58000040,0xd65f03c0};
    const uint64_t Literal=0x12345678abcdef01ULL+I;
    std::memcpy(Private.Ptr,Instructions,sizeof(Instructions));
    std::memcpy(Private.Ptr+8,&Literal,sizeof(Literal));
    CompiledCode Code {};Code.BlockBegin=Private.Ptr;Code.Size=16;
    Code.EntryPoints.emplace(0x3000,Private.Ptr);Code.PearPendingEmission=true;
    JIT->PearPendingTemp=Private.Ptr;JIT->PearPendingSize=16;
    const auto Before=JIT->CurrentCodeBuffer->GetPearSnapshot();
    PearFiniteCheckpoint=0x18b;
    if (!JIT->BeginPreparedPublication(Code)) return {PEAR_FEX_UNAVAILABLE,0,0};
    if (!I) {
      // A legitimate generation-invalidated publication must abort cleanly.
      // The updated owner token must be visible before any following writer.
      PearFiniteCheckpoint=0x18c;
      if (JIT->FinishPreparedPublication(Code,false)) return {PEAR_FEX_STALE_IDENTITY,0,0};
      PearFiniteCheckpoint=0x18d;
      const auto After=JIT->CurrentCodeBuffer->GetPearSnapshot();
      if (JIT->PearWriter || JIT->PearPendingTemp || JIT->PearPreparedBuffer ||
          Code.PearOwnerPublished || !M::Retirement::AdmissionOpen() ||
          After.Token.allocation_id!=Before.Token.allocation_id || After.Token.generation!=Before.Token.generation ||
          After.Token.expected_state!=PEAR_FEX_PUBLISHED_RX || After.Base!=Before.Base ||
          After.Token.write_epoch<=Before.Token.write_epoch) return {PEAR_FEX_STALE_IDENTITY,0,0};
    } else {
      bool Published {};
      {
        auto Lock=GuardSignalDeferringSection<std::shared_lock>(C->CodeInvalidationMutex,Thread);
        Published=JIT->FinishPreparedPublication(Code,Life.Validate() && JIT->ThreadState==Thread &&
          Thread->LookupCache->Shared==JIT->CurrentCodeBuffer->LookupCache.get());
      }
      if (!Published || !Code.PearOwnerPublished || Code.PearPendingEmission || Code.EntryPoints.size()!=1 ||
          Code.EntryPoints.begin()->second!=Code.BlockBegin || JIT->PearPendingTemp || JIT->PearWriter)
        return {PEAR_FEX_STALE_IDENTITY,0,0};
    }
    Outcome=C->FinishPearDispatcherGate(Gate);if (!Outcome) return Outcome;
    if (I) {
      auto Window=JIT->FindPearManagedWindow(reinterpret_cast<uintptr_t>(Code.BlockBegin));
      auto Target=JIT->FindPearRetainedTarget(reinterpret_cast<uintptr_t>(Code.BlockBegin));
      if (!Window || !Target || Window->Offset!=Code.HostCodeOffset) return {PEAR_FEX_UNAVAILABLE,0,0};
      std::array<uint8_t,16> Observed {};
      const auto Read=M::CopyManagedRXUnderGlobalLease(C->Dispatcher->GetPearSnapshot(),*Target,Thread,Window->Offset,Observed);
      if (!Read) return Read.Outcome;
      if (std::memcmp(Observed.data(),Instructions,8) || std::memcmp(Observed.data()+8,&Literal,8))
        return {PEAR_FEX_STALE_IDENTITY,0,0};
      if (reinterpret_cast<uint64_t (*)()>(Code.BlockBegin)()!=Literal) return {PEAR_FEX_STALE_IDENTITY,0,0};
    }
  }
  return {PEAR_FEX_OK,0,0};
}
FEXCore::Utils::PearFEXMemory::Result Arm64JITCore::ExecutePearFiniteBufferGrowth(
    FEXCore::Core::CpuStateFrame* Frame, uintptr_t ResumePC) {
  namespace M=FEXCore::Utils::PearFEXMemory;
  auto Life=M::AcquireCurrentSourceLifetime();
  auto* Thread=Life ? Life.ActualThread() : nullptr;
  auto* C=Life ? const_cast<FEXCore::Context::ContextImpl*>(
    static_cast<const FEXCore::Context::ContextImpl*>(Life.ActualContext())) : nullptr;
  if (!Thread || !C || Frame!=Thread->CurrentFrame || Frame->Thread!=Thread || !Thread->CPUBackend ||
      !C->Dispatcher || Frame->SignalHandlerRefCounter || !M::HasManagedActive(C->Dispatcher->GetPearSnapshot()))
    return {PEAR_FEX_UNAVAILABLE,0,0};
  auto* JIT=static_cast<Arm64JITCore*>(Thread->CPUBackend.get());
  FEXCore::Context::ContextImpl::PearDispatcherGate Gate {};
  auto Outcome=C->BeginPearDispatcherGate(Frame,ResumePC,Gate);if (!Outcome) return Outcome;
  for (uint32_t I=0;I<4;++I) {
    PearFiniteCheckpoint=0x200+I;
    auto Held=JIT->CurrentCodeBuffer;
    if (!Held || JIT->PearWriter || JIT->PearPendingTemp ||
        Thread->LookupCache->Shared!=Held->LookupCache.get()) return {PEAR_FEX_UNAVAILABLE,0,0};
    auto Facts=Held->GetPearSnapshot();
    const auto Size=std::min<size_t>(Held->TotalAllocationSize()*2,128ULL*1024*1024);
    std::weak_ptr<CodeBuffer> Weak=Held;
    // Invoke actual upstream manager growth, backend replacement and lookup
    // switching. The fixture supplies no guest address or signal context.
    JIT->ClearCache();
    if (!Life.Validate() || !JIT->CurrentCodeBuffer || JIT->CurrentCodeBuffer==Held ||
        JIT->CurrentCodeBuffer!=JIT->SharedCodeBuffers.GetLatest() ||
        JIT->CurrentCodeBuffer->TotalAllocationSize()!=Size || JIT->CurrentCodeBuffer->AllocatedSpaceUsed() ||
        Thread->LookupCache->Shared!=JIT->CurrentCodeBuffer->LookupCache.get() || Weak.expired())
      return {PEAR_FEX_STALE_IDENTITY,0,0};
    Outcome=M::Retirement::DrainAtNativeGate();if (!Outcome) return Outcome;
    // A held old source generation must still own its native extent. Restore
    // unchanged RX bytes for the first buffer; later virgin buffers use Abort.
    const auto Before=Held->GetPearSnapshot();auto Transaction=Before;
    {
      M::WriteGuard Probe{Transaction,0,16};if (!Probe) return Probe.Status();
      Outcome=Before.Token.expected_state==PEAR_FEX_PUBLISHED_RX ? Probe.Publish() : Probe.Abort();
      if (!Outcome) return Outcome;
      if (!Held->ComparePearUpdate(Before,Transaction))
        return M::Retirement::PoisonSourceAdmission({PEAR_FEX_STALE_IDENTITY,0,0});
    }
    Facts=Held->GetPearSnapshot();
    if (!I) Frame->State.InlineJITBlockHeader=0;
    Held.reset();
    if (!Weak.expired()) return {PEAR_FEX_STALE_IDENTITY,0,0};
    Outcome=M::Retirement::DrainAtNativeGate();if (!Outcome) return Outcome;
    const auto Stale=M::Retire(Facts);
    if (Stale.Status!=PEAR_FEX_STALE_IDENTITY || Stale.ErrorDomain || Stale.ErrorCode)
      return {PEAR_FEX_STALE_IDENTITY,0,0};
  }
  return C->FinishPearDispatcherGate(Gate);
}

#endif

void Arm64JITCore::Op_NoOp(const IR::IROp_Header* IROp, IR::Ref Node) {}

Arm64JITCore::Arm64JITCore(FEXCore::Context::ContextImpl* ctx, FEXCore::Core::InternalThreadState* Thread
#ifdef PEAR_FEX_MEMORY_OWNER
  , fextl::shared_ptr<CodeBuffer> InitialBuffer
#endif
)
  : CPUBackend(*ctx, Thread)
  , Arm64Emitter(ctx)
  , HostSupportsSVE128 {ctx->HostFeatures.SupportsSVE128 != 0}
  , HostSupportsSVE256 {ctx->HostFeatures.SupportsSVE256 != 0}
  , HostSupportsAVX256 {ctx->HostFeatures.SupportsAVX && ctx->HostFeatures.SupportsSVE256}
  , HostSupportsRPRES {ctx->HostFeatures.SupportsRPRES != 0}
  , HostSupportsAFP {ctx->HostFeatures.SupportsAFP != 0}
  , CTX {ctx}
  , TempCodeBufferAllocator(ctx->CPUBackendAllocator, 0) {

  RAPass = Thread->PassManager->GetPass<IR::RegisterAllocationPass>("RA");

  RAPass->AddRegisters(IR::RegClass::GPR, GeneralRegisters.size());
  RAPass->AddRegisters(IR::RegClass::GPRFixed, StaticRegisters.size());
  RAPass->AddRegisters(IR::RegClass::FPR, GeneralFPRegisters.size());
  RAPass->AddRegisters(IR::RegClass::FPRFixed, StaticFPRegisters.size());
  RAPass->SetNumPairRegs(PairRegisters);

  {
    // Set up pointers that the JIT needs to load

    // Common
    auto& Ptrs = ThreadState->CurrentFrame->Pointers;

    Ptrs.PrintValue = reinterpret_cast<uint64_t>(PrintValue);
    Ptrs.PrintVectorValue = reinterpret_cast<uint64_t>(PrintVectorValue);
    Ptrs.PrintMsgValue = reinterpret_cast<uint64_t>(PrintMsg);

    Ptrs.ThreadRemoveCodeEntryFromJIT = reinterpret_cast<uintptr_t>(&Context::ContextImpl::ThreadRemoveCodeEntryFromJit);
    Ptrs.MonoBackpatcherWrite = reinterpret_cast<uint64_t>(&Context::ContextImpl::MonoBackpatcherWrite);
    Ptrs.CPUIDObj = reinterpret_cast<uint64_t>(&CTX->CPUID);

    {
      FEXCore::Utils::MemberFunctionToPointerCast PMF(&FEXCore::CPUIDEmu::RunFunction);
      Ptrs.CPUIDFunction = PMF.GetConvertedPointer();
    }

    {
      FEXCore::Utils::MemberFunctionToPointerCast PMF(&FEXCore::CPUIDEmu::RunXCRFunction);
      Ptrs.XCRFunction = PMF.GetConvertedPointer();
    }

    {
      FEXCore::Utils::MemberFunctionToPointerCast PMF(&FEXCore::HLE::SyscallHandler::HandleSyscall);
      Ptrs.SyscallHandlerObj = reinterpret_cast<uint64_t>(CTX->SyscallHandler);
      Ptrs.SyscallHandlerFunc = PMF.GetVTableEntry(CTX->SyscallHandler);
    }
#ifdef PEAR_FEX_MEMORY_OWNER
    Ptrs.ExitFunctionLink = reinterpret_cast<uintptr_t>(&Arm64JITCore::ExitPearFunctionLink);
#else
    Ptrs.ExitFunctionLink = reinterpret_cast<uintptr_t>(&Arm64JITCore::ExitFunctionLink);
#endif
    Ptrs.LUDIV = reinterpret_cast<uint64_t>(LUDIV);
    Ptrs.LDIV = reinterpret_cast<uint64_t>(LDIV);
    Ptrs.RDRANDFallback = reinterpret_cast<uint64_t>(RDRANDFallback);
  }

#ifdef PEAR_FEX_MEMORY_OWNER
  // The real source thread gate acquired this exact retained buffer before
  // compiler construction. A concurrent Latest replacement cannot trigger a
  // hidden owner wait or change the allocation selected for this constructor.
  CurrentCodeBuffer = std::move(InitialBuffer);
#else
  CurrentCodeBuffer = SharedCodeBuffers.GetLatest();
#endif
  ThreadState->LookupCache->Shared = CurrentCodeBuffer->LookupCache.get();
}

void Arm64JITCore::ClearCache() {
  // NOTE: Holding on to the reference here is required to ensure validity of the WriteLock mutex
  auto PrevCodeBuffer = CurrentCodeBuffer;
#ifdef PEAR_FEX_MEMORY_OWNER
  // A new owner constructor can wait for native acknowledgement. Complete it
  // before taking the old generation's lookup lock; retain its signal refs.
  auto CodeBuffer = AcquireNewSharedCodeBuffer();
  auto lk = PrevCodeBuffer->LookupCache->AcquireWriteLock();
#else
  auto lk = PrevCodeBuffer->LookupCache->AcquireWriteLock();
  auto CodeBuffer = AcquireNewSharedCodeBuffer();
#endif
  ThreadState->LookupCache->ChangeGuestToHostMapping(*PrevCodeBuffer, *CodeBuffer->LookupCache, lk);
}

Arm64JITCore::~Arm64JITCore() {}

bool Arm64JITCore::IsInlineConstant(const IR::OrderedNodeWrapper& WNode, uint64_t* Value) const {
  if (WNode.IsImmediate()) {
    return false;
  }

  auto OpHeader = IR->GetOp<IR::IROp_Header>(WNode);

  if (OpHeader->Op == IR::IROps::OP_INLINECONSTANT) {
    auto Op = OpHeader->C<IR::IROp_InlineConstant>();
    if (Value) {
      *Value = Op->Constant;
    }
    return true;
  } else {
    return false;
  }
}

bool Arm64JITCore::IsInlineEntrypointOffset(const IR::OrderedNodeWrapper& WNode, uint64_t* Value) const {
  if (WNode.IsImmediate()) {
    return false;
  }

  auto OpHeader = IR->GetOp<IR::IROp_Header>(WNode);

  if (OpHeader->Op == IR::IROps::OP_INLINEENTRYPOINTOFFSET) {
    auto Op = OpHeader->C<IR::IROp_InlineEntrypointOffset>();
    if (Value) {
      uint64_t Mask = ~0ULL;
      const auto Size = OpHeader->Size;
      if (Size == IR::OpSize::i32Bit) {
        Mask = 0xFFFF'FFFFULL;
      }
      *Value = (Entry + Op->Offset) & Mask;
    }
    return true;
  } else {
    return false;
  }
}

void Arm64JITCore::EmitTFCheck() {
  ARMEmitter::ForwardLabel l_TFUnset;
  ARMEmitter::ForwardLabel l_TFBlocked;

  // Note that this needs to be before the below suspend checks, as X86 checks this flag immediately after executing an instruction.
  ldrb(TMP1, STATE_PTR(CpuStateFrame, State.flags[X86State::RFLAG_TF_RAW_LOC]));

  (void)cbz(ARMEmitter::Size::i32Bit, TMP1, &l_TFUnset);

  // X86 semantically checks TF after executing each instruction, so e.g. setting a context with TF set will execute a single instruction
  // and then raise an exception. However on the FEX side this is simpler to implement by checking at the start of each instruction, handle this by having bit 1 being unset in the flag state indicate that TF is blocked for a single instruction.
  (void)tbz(TMP1, 1, &l_TFBlocked);

  // Block TF for a single instruction when the frontend jumps to a new context by unsetting bit 1.
  ldrb(TMP1, STATE_PTR(CpuStateFrame, State.flags[X86State::RFLAG_TF_RAW_LOC]));
  and_(ARMEmitter::Size::i32Bit, TMP1, TMP1, ~(1 << 1));
  strb(TMP1, STATE_PTR(CpuStateFrame, State.flags[X86State::RFLAG_TF_RAW_LOC]));

  Core::CpuStateFrame::SynchronousFaultDataStruct State = {
    .FaultToTopAndGeneratedException = 1,
    .Signal = Core::FAULT_SIGTRAP,
    .TrapNo = X86State::X86_TRAPNO_DB,
    .si_code = 2,
    .err_code = 0,
  };

  uint64_t Constant {};
  memcpy(&Constant, &State, sizeof(State));

  LoadConstant(ARMEmitter::Size::i64Bit, TMP1, Constant);
  str(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, SynchronousFaultData));
  ldr(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.GuestSignal_SIGTRAP));
  br(TMP1);

  (void)Bind(&l_TFBlocked);
  // If TF was blocked for this instruction, unblock it for the next.
  LoadConstant(ARMEmitter::Size::i32Bit, TMP1, 0b11);
  strb(TMP1, STATE_PTR(CpuStateFrame, State.flags[X86State::RFLAG_TF_RAW_LOC]));
  (void)Bind(&l_TFUnset);
}

void Arm64JITCore::EmitSuspendInterruptCheck() {
  if (CTX->Config.NeedsPendingInterruptFaultCheck) {
    // Trigger a fault if there are any pending interrupts
    // Used only for gdbserver at the moment
    constexpr size_t InterruptPageOffset =
      offsetof(FEXCore::Core::InternalThreadState, InterruptFaultPage) - offsetof(FEXCore::Core::InternalThreadState, BaseFrameState);
    if constexpr (InterruptPageOffset <= 32760) {
      str(ARMEmitter::XReg::zr, STATE, InterruptPageOffset);
    } else {
      // Need to use vector 128-bit store for this range.
      // Doesn't matter which register we use to store.
      str(ARMEmitter::QReg::q0, STATE, InterruptPageOffset);
    }
  }

#ifdef _WIN32
  static constexpr uint16_t SuspendMagic {0xCAFE};

  ldr(TMP2.W(), STATE_PTR(CpuStateFrame, SuspendDoorbell));
  ARMEmitter::ForwardLabel l_NoSuspend;
  (void)cbz(ARMEmitter::Size::i32Bit, TMP2, &l_NoSuspend);
  brk(SuspendMagic);
  (void)Bind(&l_NoSuspend);
#endif
}

#include "PearPhaseJIT.inc"

void Arm64JITCore::EmitEntryPoint(ARMEmitter::BackwardLabel& HeaderLabel, bool CheckTF) {
  // Get the address of the JITCodeHeader and store in to the core state.
  // Two instruction cost, each 1 cycle.
  adr_OrRestart(TMP1, &HeaderLabel);
  str(TMP1, STATE, offsetof(FEXCore::Core::CPUState, InlineJITBlockHeader));

  if (CheckTF) {
    EmitTFCheck();
  }

  if (SpillSlots) {
    const auto TotalSpillSlotsSize = SpillSlots * MaxSpillSlotSize;

    if (ARMEmitter::IsImmAddSub(TotalSpillSlotsSize)) {
      sub(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::rsp, ARMEmitter::Reg::rsp, TotalSpillSlotsSize);
    } else {
      LoadConstant(ARMEmitter::Size::i64Bit, TMP1, TotalSpillSlotsSize);
      sub(ARMEmitter::Size::i64Bit, ARMEmitter::XReg::rsp, ARMEmitter::XReg::rsp, TMP1, ARMEmitter::ExtendedType::LSL_64, 0);
    }
  }

  EmitSuspendInterruptCheck();
}


CodeBuffer::CodeBufferAllocation Arm64JITCore::AllocateCodeBufferInSharedCache(size_t Size) {
  CodeBuffer::CodeBufferAllocation AllocatedInfo {};
  PEAR_FEX_REQUIRE(CurrentCodeBuffer->LookupCache.get() == ThreadState->LookupCache->Shared, "INVARIANT VIOLATED: SharedLookupCache "
                                                                                               "doesn't match up!\n");
  // Bring CodeBuffer up to date
  if (auto Prev = CheckCodeBufferUpdate()) {
    Allocator::VirtualDontNeed(ThreadState->CallRetStackBase, FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE);
    auto lk = ThreadState->LookupCache->AcquireWriteLock();
    ThreadState->LookupCache->ChangeGuestToHostMapping(*Prev, *CurrentCodeBuffer->LookupCache, lk);
  }

#ifdef PEAR_FEX_MEMORY_OWNER
  // Preserve geometric growth, but exhaustion has a finite checked result.
  if (!Size || Size > 128ULL*1024*1024-FEXCore::Utils::FEX_PAGE_SIZE) return {};
  AllocatedInfo = CurrentCodeBuffer->AtomicAllocateBuffer(Size);
  if (!AllocatedInfo.BufferAllocationOffset) {
    CTX->ClearCodeCache(ThreadState);
    AllocatedInfo = CurrentCodeBuffer->AtomicAllocateBuffer(Size);
  }
  return AllocatedInfo;
#else
  // Attempt to allocate a buffer from the SharedCodeBuffers.
  while (AllocatedInfo.BufferAllocationOffset == nullptr) {
    AllocatedInfo = CurrentCodeBuffer->AtomicAllocateBuffer(Size);

    if (AllocatedInfo.BufferAllocationOffset == nullptr) {
      // If it didn't fit then clear the buffer and try again.
      // This has the possibility of migrating the SharedCodeBuffer. See above in `Arm64JITCore::ClearCache()`
      CTX->ClearCodeCache(ThreadState);
      continue;
    }
  }

  return AllocatedInfo;
#endif
}

CPUBackend::CompiledCode Arm64JITCore::CompileCode(uint64_t Entry, uint64_t Size, bool SingleInst, const FEXCore::IR::IRListView* IR,
                                                   FEXCore::Core::DebugData* DebugData, bool CheckTF) {
  FEXCORE_PROFILE_SCOPED("Arm64::CompileCode");
#ifdef PEAR_FEX_MEMORY_OWNER
  PEAR_FEX_REQUIRE(!PearPendingTemp && !PearWriter, "Pear backend already owns pending emission");
#endif
  const auto PrevNumAllocations = Relocations.size();

  this->Entry = Entry;
  this->DebugData = DebugData;
  this->IR = IR;
  RequiresFarARM64Jumps = false;
  SSANodeMultiplier = 24;

  // Prepare restart via long jump in case branch encoding fails.
  // This uses UncheckedLongJump since we don't implement std::longjmp in WoA setups
  switch (static_cast<RestartOptions::Control>(FEXCore::UncheckedLongJump::SetJump(ThreadState->RestartJump))) {
  case RestartOptions::Control::Incoming:
    // Nothing
    break;
  case RestartOptions::Control::EnableFarARM64Jumps: RequiresFarARM64Jumps = true; break;
  case RestartOptions::Control::NeedsLargerJITSpace:
    // Get rid of the claimed buffer immediately, we can't fit in it at all.
    TempCodeBufferAllocator.UnclaimBuffer();
    SSANodeMultiplier *= 2;
    break;
  default: LOGMAN_MSG_A_FMT("Unhandled Arm64 restart condition!");
  }

  uint32_t SSACount = IR->GetSSACount();
  JumpTargets.clear();
  CallReturnTargets.clear();
  PendingJumpThunks.clear();
  JumpTargets.resize(IR->GetHeader()->BlockCount, {});
  Relocations.resize(PrevNumAllocations, FEXCore::CPU::Relocation::Default()); // Discard any relocations generated from a previous attempt

  CodeData.EntryPoints.clear();

  // Fairly excessive buffer range to make sure we don't overflow
  // One page baseline, plus SSANodeMultipler bytes, plus another page for guard page.
#ifdef PEAR_FEX_MEMORY_OWNER
  const uint64_t RequestedRange = uint64_t(FEXCore::Utils::FEX_PAGE_SIZE)*2 + uint64_t(SSACount)*SSANodeMultiplier;
  PEAR_FEX_REQUIRE(RequestedRange <= 16ULL*1024*1024-FEXCore::Utils::FEX_PAGE_SIZE,
                    "Pear private NX emission exceeds its approved16MiB bound");
  const uint32_t DesiredBufferRange = AlignUp(static_cast<uint32_t>(RequestedRange), FEXCore::Utils::FEX_PAGE_SIZE);
#else
  const uint32_t DesiredBufferRange = AlignUp(FEXCore::Utils::FEX_PAGE_SIZE * 2 + SSACount * SSANodeMultiplier, FEXCore::Utils::FEX_PAGE_SIZE);
#endif

  // JIT output is first written to a temporary buffer and later relocated to the CodeBuffer.
  // This minimizes lock contention of CodeBufferWriteMutex.
  auto TempCodeBufferInfo = TempCodeBufferAllocator.ReownOrClaimBufferWithSize(DesiredBufferRange);
  auto TempCodeBuffer = TempCodeBufferInfo.Ptr;
#ifdef PEAR_FEX_MEMORY_OWNER
  PEAR_FEX_REQUIRE(TempCodeBuffer && TempCodeBufferInfo.Size > FEXCore::Utils::FEX_PAGE_SIZE &&
                    TempCodeBufferInfo.Size <= 16ULL*1024*1024, "Pear private NX allocator exceeded its finite bound");
#endif
  const uint32_t UsableBufferRange = TempCodeBufferInfo.Size - FEXCore::Utils::FEX_PAGE_SIZE;
#ifdef PEAR_FEX_MEMORY_OWNER
  const auto InPrivateBuffer = [TempCodeBuffer, UsableBufferRange](const void* Address, size_t Bytes) {
    const auto Base = reinterpret_cast<uintptr_t>(TempCodeBuffer);
    const auto Value = reinterpret_cast<uintptr_t>(Address);
    return Value >= Base && Value-Base <= UsableBufferRange && Bytes <= UsableBufferRange-(Value-Base);
  };
#endif
#ifdef PEAR_FEX_MEMORY_OWNER
  // CompileCode already rejects an active owner writer. The allocator above
  // supplies the existing ordinary NX staging buffer; publication is later.
  SetPrivateStagingBuffer(TempCodeBuffer, UsableBufferRange);
#else
  SetBuffer(TempCodeBuffer, UsableBufferRange);
#endif

  ThreadState->JITGuardPage = reinterpret_cast<uintptr_t>(TempCodeBuffer) + UsableBufferRange;
  ThreadState->JITGuardOverflowArgument = FEXCore::ToUnderlying(RestartOptions::Control::NeedsLargerJITSpace);

  CodeData.BlockBegin = GetCursorAddress<uint8_t*>();
  PEAR_FEX_REQUIRE(GetCursorOffset() == 0, "Needs to be zero");

  // Put the code header at the start of the data block.
  ARMEmitter::BackwardLabel JITCodeHeaderLabel {};
  (void)Bind(&JITCodeHeaderLabel);
  JITCodeHeader* CodeHeader = GetCursorAddress<JITCodeHeader*>();
  CursorIncrement(sizeof(JITCodeHeader));

  auto CodeBegin = GetCursorAddress<uint8_t*>();

  // AAPCS64
  // r30      = LR
  // r29      = FP
  // r19..r28 = Callee saved
  // r18      = Platform Register (Matters if we target Windows or iOS)
  // r16..r17 = Inter-procedure scratch
  //  r9..r15 = Temp
  //  r8      = Indirect Result
  //  r0...r7 = Parameter/Results
  //
  //  FPRS:
  //  v8..v15 = (lower 64bits) Callee saved

  // Our allocation:
  // X0 = ThreadState
  // X1 = MemBase
  //
  // X1-X3 = Temp
  // X4-r18 = RA

  SpillSlots = IR->SpillSlots();

  PendingTargetLabel = nullptr;
  PendingCallReturnTargetLabel = nullptr;

  for (auto [BlockNode, BlockHeader] : IR->GetBlocks()) {
    auto BlockIROp = BlockHeader->CW<FEXCore::IR::IROp_CodeBlock>();
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
    PEAR_FEX_REQUIRE(BlockIROp->Header.Op == IR::OP_CODEBLOCK, "IR type failed to be a code block");
#endif

    auto BlockStartHostCode = GetCursorAddress<uint8_t*>();
    {
      const auto Node = IR->GetID(BlockNode);
      const auto Target = &JumpTargets[BlockIROp->ID];

      // if there's a pending branch, and it is not fall-through
      if (PendingTargetLabel && PendingTargetLabel != Target) {
        if (PendingTargetLabel->Backward.Location) {
          EmitSuspendInterruptCheck();
        }
        b_OrRestart(PendingTargetLabel);
        PendingTargetLabel = nullptr;
      }

      if (BlockIROp->EntryPoint) {
        uint64_t BlockStartRIP = Entry + BlockIROp->GuestEntryOffset;

        const auto IsReturnTarget = CallReturnTargets.try_emplace(Node).first;
        if (PendingTargetLabel) {
          // If there is a fallthrough branch to this block, skip over the entrypoint code.
          b_OrRestart(Target);
        } else if (PendingCallReturnTargetLabel && PendingCallReturnTargetLabel != &IsReturnTarget->second) {
          // If we just emitted a call, but the block we're now emitting is not the return block so don't fallthrough.
          b_OrRestart(PendingCallReturnTargetLabel);
        }
        PendingCallReturnTargetLabel = nullptr;

        BindOrRestart(&IsReturnTarget->second);
        CodeData.EntryPoints.emplace(BlockStartRIP, GetCursorAddress<uint8_t*>());
        DebugData->GuestOpcodes.push_back({BlockIROp->GuestEntryOffset, GetCursorAddress<uint8_t*>() - CodeData.BlockBegin});

        EmitEntryPoint(JITCodeHeaderLabel, CheckTF);
      }

      if (PendingCallReturnTargetLabel) {
        // If there is still a pending call return target, then the block we're emitting is not the return block so don't fallthrough.
        b_OrRestart(PendingCallReturnTargetLabel);
        PendingCallReturnTargetLabel = nullptr;
      }
      PendingTargetLabel = nullptr;

      BindOrRestart(Target);
#ifdef PEAR_PHASE_OBSERVE
      if (BlockIROp->EntryPoint) EmitPearPhase(Entry + BlockIROp->GuestEntryOffset, false);
#endif
    }

    for (auto [CodeNode, IROp] : IR->GetCode(BlockNode)) {
      switch (IROp->Op) {
#define REGISTER_OP(op, x) \
  case FEXCore::IR::IROps::OP_##op: Op_##x(IROp, CodeNode); break

#define IROP_DISPATCH_DISPATCH
#include <FEXCore/IR/IRDefines_Dispatch.inc>
#undef REGISTER_OP

      default: Op_Unhandled(IROp, CodeNode); break;
      }
    }

    DebugData->Subblocks.push_back({static_cast<uint32_t>(BlockStartHostCode - CodeData.BlockBegin),
                                    static_cast<uint32_t>(GetCursorAddress<uint8_t*>() - BlockStartHostCode)});
  }

  // Make sure last branch is generated. It certainly can't be eliminated here.
  if (PendingTargetLabel) {
    if (PendingTargetLabel->Backward.Location) {
      EmitSuspendInterruptCheck();
    }
    b_OrRestart(PendingTargetLabel);
  }
  PendingTargetLabel = nullptr;

  ARMEmitter::ForwardLabel l_ExitLink;
  for (auto& PendingJumpThunk : PendingJumpThunks) {
    // Align as 64-bit atomics are used on the HostCode field.
    Align(8);

    ARMEmitter::ForwardLabel l_DoLink;
    uint64_t ThunkAddress = GetCursorAddress<uint64_t>();
    BindOrRestart(&PendingJumpThunk.Label);
    b_OrRestart(&l_DoLink);
    br(TMP1);
    BindOrRestart(&l_DoLink);
    ldr(TMP1, &l_ExitLink);
    blr(TMP1);

    // This is a ExitFunctionLinkData struct
    BindOrRestart(&l_ExitLink);
    dc64(0); // HostCode
    if (PendingJumpThunk.PatchSiteAddress) {
      // GuestRIP with an extra step
      PlaceNamedSymbolLiteral(
        InsertGuestPatchableRIPLiteral(PendingJumpThunk.GuestRIP, PendingJumpThunk.PatchSiteAddress, PendingJumpThunk.PatchSiteSize));
    } else {
      PlaceNamedSymbolLiteral(InsertGuestRIPLiteral(PendingJumpThunk.GuestRIP)); // GuestRIP
    }
    dc64(PendingJumpThunk.CallerAddress - ThunkAddress); // CallerOffset
  }

  BindOrRestart(&l_ExitLink);
  PlaceNamedSymbolLiteral(InsertNamedSymbolLiteral(RelocNamedSymbolLiteral::NamedSymbol::SYMBOL_LITERAL_EXITFUNCTION_LINKER));

  // CodeSize not including the header or tail data.
#ifdef PEAR_FEX_MEMORY_OWNER
  [[maybe_unused]]
#endif
  const uint64_t CodeOnlySize = GetCursorAddress<uint8_t*>() - CodeBegin;

  // Add the JitCodeTail (written later)
  Align(alignof(JITCodeTail));
  const auto JITBlockTailLocation = GetCursorAddress<uint8_t*>();
#ifdef PEAR_FEX_MEMORY_OWNER
  PEAR_FEX_REQUIRE(InPrivateBuffer(CodeHeader, sizeof(*CodeHeader)) &&
                    InPrivateBuffer(JITBlockTailLocation, sizeof(JITCodeTail)), "Pear private tail/header range refused");
#endif
  CodeHeader->OffsetToBlockTail = JITBlockTailLocation - CodeData.BlockBegin;

  JITCodeTail JITBlockTail {
    .RIP = Entry,
    .GuestSize = Size,
    .SpinLockFutex = 0,
    .SingleInst = SingleInst,
  };

  // Entries that live after the JITCodeTail.
  // These entries correlate JIT code regions with guest RIP regions.
  // Using these entries FEX is able to reconstruct the guest RIP accurately when an instruction cause a signal fault.
  // Packed using two variable length integer entries to ensure the size isn't too large.
  // These smaller sizes means that each entry is relative to each other instead of absolute offset from the start of the JIT block.
  // When reconstructing the RIP, each entry must be walked linearly and accumulated with the previous entries.
  // This is a trade-off between compression inside the JIT code space and execution time when reconstruction the RIP.
  // RIP reconstruction when faulting is less likely so we are requiring the accumulation.
  //
  // struct {
  //   // The Host PC offset from the previous entry.
  //   FEXCore::Utils::vl64 HostPCOffset;
  //   // How much to offset the RIP from the previous entry.
  //   FEXCore::Utils::vl64 GuestRIPOffset;
  // };

  const auto JITRIPEntriesBegin = JITBlockTailLocation + sizeof(JITBlockTail);
  auto JITRIPEntriesLocation = JITRIPEntriesBegin;

  {
    // Store the RIP entries.
    JITBlockTail.NumberOfRIPEntries = DebugData->GuestOpcodes.size();
    JITBlockTail.OffsetToRIPEntries = JITRIPEntriesBegin - JITBlockTailLocation;
    uintptr_t CurrentRIPOffset = 0;
    uint64_t CurrentPCOffset = 0;

    for (size_t i = 0; i < DebugData->GuestOpcodes.size(); i++) {
      const auto& GuestOpcode = DebugData->GuestOpcodes[i];
      int64_t HostPCOffset = GuestOpcode.HostEntryOffset - CurrentPCOffset;
      int64_t GuestRIPOffset = GuestOpcode.GuestEntryOffset - CurrentRIPOffset;

#ifdef PEAR_FEX_MEMORY_OWNER
      PEAR_FEX_REQUIRE(InPrivateBuffer(JITRIPEntriesLocation, FEXCore::Utils::vl64pair::EncodedSize(HostPCOffset, GuestRIPOffset)),
                        "Pear private variable-length metadata range refused");
#endif
      JITRIPEntriesLocation += FEXCore::Utils::vl64pair::Encode(JITRIPEntriesLocation, HostPCOffset, GuestRIPOffset);

      CurrentPCOffset = GuestOpcode.HostEntryOffset;
      CurrentRIPOffset = GuestOpcode.GuestEntryOffset;
    }
  }

  SetCursorOffset(JITRIPEntriesLocation - CodeData.BlockBegin);
  // Make sure code is 16B aligned on the tail.
  // Can't use Align16B here as vl64pair can cause non-4byte alignment.
  Align(16);

  // Beginning of emission is guaranteed to be offset zero. So the code data size is just the current cursor offset.
  CodeData.Size = GetCursorOffset();

  // Finalize and write block tail data
  JITBlockTail.Size = CodeData.Size;
  {
    memcpy(JITBlockTailLocation, &JITBlockTail, sizeof(JITBlockTail));
    SetCursorOffset(JITBlockTailLocation - CodeData.BlockBegin + offsetof(JITCodeTail, RIP));
    PlaceNamedSymbolLiteral(InsertGuestRIPLiteral(JITBlockTail.RIP));

    // Emitter buffer is no longer used, guard against misuse by setting to nullptr.
    SetBuffer(nullptr, 0);
  }

#ifdef PEAR_FEX_MEMORY_OWNER
  // Keep the original temporary emission owned and NX until the outer core
  // releases its first invalidation scope and obtains the exact owner window.
  PEAR_FEX_REQUIRE(CodeData.Size && CodeData.Size <= UsableBufferRange && !(CodeData.Size & 15),
                    "Pear private emission result range refused");
  PearPendingTemp = TempCodeBuffer; PearPendingSize = CodeData.Size;
  CodeData.PearPendingEmission = true; CodeData.PearOwnerPublished = false;
#else
  // Migrate the compile output from temporary storage to the actual CodeBuffer.
  {
    LOGMAN_THROW_A_FMT(CodeData.Size % 16 == 0, "Needs to be 16B aligned!");

    auto AllocatedInfo = AllocateCodeBufferInSharedCache(CodeData.Size);
    // NOTE: 16-byte alignment of the new cursor offset must be preserved for block linking records
    LOGMAN_THROW_A_FMT((reinterpret_cast<uintptr_t>(AllocatedInfo.BufferAllocationOffset) % 16) == 0, "Allocated buffer wasn't 16B "
                                                                                                      "aligned?");

    // Adjust host addresses
    const auto Delta = AllocatedInfo.BufferAllocationOffset - CodeData.BlockBegin;
    CodeData.BlockBegin += Delta;
    for (auto& EntryPoint : CodeData.EntryPoints) {
      EntryPoint.second += Delta;
    }
    CodeBegin += Delta;
    CodeData.HostCodeOffset = CodeData.BlockBegin - CurrentCodeBuffer->GetBufferBase();

    // Copy over CodeBuffer contents
    memcpy(AllocatedInfo.BufferAllocationOffset, TempCodeBuffer, CodeData.Size);
  }

  TempCodeBufferAllocator.DelayedDisownBuffer();

  ClearICache(CodeBegin, CodeOnlySize);
#endif
#ifdef VIXL_DISASSEMBLER
  if (Disassemble() & FEXCore::Config::Disassemble::STATS) {
    auto HeaderOp = IR->GetHeader();
    PEAR_FEX_REQUIRE(HeaderOp->Header.Op == IR::OP_IRHEADER, "First op wasn't IRHeader");

    LogMan::Msg::IFmt("RIP: 0x{:x}", Entry);
    LogMan::Msg::IFmt("Guest Code instructions: {}", HeaderOp->NumHostInstructions);
    LogMan::Msg::IFmt("Host Code instructions: {}", CodeOnlySize >> 2);
    LogMan::Msg::IFmt("Blow-up Amt: {}x", double(CodeOnlySize >> 2) / double(HeaderOp->NumHostInstructions));
  }

  if (Disassemble() & FEXCore::Config::Disassemble::BLOCKS) {
    const auto DisasmBegin = reinterpret_cast<const vixl::aarch64::Instruction*>(CodeBegin);
    const auto DisasmEnd = reinterpret_cast<const vixl::aarch64::Instruction*>(CodeBegin + CodeOnlySize);
    LogMan::Msg::IFmt("Disassemble Begin");
    for (auto PCToDecode = DisasmBegin; PCToDecode < DisasmEnd; PCToDecode += 4) {
      DisasmDecoder->Decode(PCToDecode);
      auto Output = Disasm->GetOutput();
      LogMan::Msg::IFmt("{}", Output);
    }
    LogMan::Msg::IFmt("Disassemble End");
  }
#endif

  DebugData->HostCodeSize = CodeData.Size;
  DebugData->Relocations = &Relocations;

  this->IR = nullptr;

  return std::move(CodeData);
}

#ifdef PEAR_FEX_MEMORY_OWNER
bool Arm64JITCore::BeginPreparedPublication(CompiledCode& Code) {
  // Called by the outer core only after its first invalidation scope ends.
  if (PearLabelFailure || !Code.PearPendingEmission || Code.PearOwnerPublished || !PearPendingTemp || PearWriter ||
      Code.BlockBegin != PearPendingTemp || Code.Size != PearPendingSize || !Code.Size || (Code.Size & 15) ||
      Code.Size > 16ULL*1024*1024 || !FEXCore::Utils::PearFEXMemory::CurrentExecutor()) {
    LogMan::Msg::EFmt("Pear pending source publication is unavailable");
    DiscardPreparedPublication(); return false;
  }
  auto Allocated = AllocateCodeBufferInSharedCache(Code.Size);
  if (!Allocated.Owner || !Allocated.BufferAllocationOffset || Allocated.Owner != CurrentCodeBuffer.get()) {
    LogMan::Msg::EFmt("Pear finite shared code allocation exhausted");
    DiscardPreparedPublication(); return false;
  }
  PearPreparedBuffer = CurrentCodeBuffer;
  const auto Base = reinterpret_cast<uintptr_t>(PearPreparedBuffer->GetBufferBase());
  const auto Destination = reinterpret_cast<uintptr_t>(Allocated.BufferAllocationOffset);
  const auto Usable = PearPreparedBuffer->UsableSize();
  if (Destination < Base || Destination-Base > Usable || Code.Size > Usable-(Destination-Base)) {
    LogMan::Msg::EFmt("Pear prepared destination range refused");
    DiscardPreparedPublication(); return false;
  }
  PearBefore = PearPreparedBuffer->GetPearSnapshot(); PearTransaction = PearBefore;
  PearPreparedDestination = Allocated.BufferAllocationOffset;
  PearWriter = FEXCore::Allocator::TryMakePearMetadataObject<FEXCore::Utils::PearFEXMemory::WriteGuard>(PearTransaction, Destination-Base, Code.Size);
  if (!PearWriter || !*PearWriter) {
    const auto Error = PearWriter ? PearWriter->Status() : FEXCore::Utils::PearFEXMemory::Result{PEAR_FEX_UNAVAILABLE,0,0};
    LogMan::Msg::EFmt("Pear source write refused: status {}, domain {}, code {}", Error.Status, Error.ErrorDomain, Error.ErrorCode);
    DiscardPreparedPublication(); return false;
  }
  if (PearWriter->Data() != PearPreparedDestination || PearTransaction.Base != PearPreparedBuffer->GetBufferBase()) {
    LogMan::Msg::EFmt("Pear source write address does not match its observed owner extent");
    DiscardPreparedPublication(); return false;
  }
  return true;
}
bool Arm64JITCore::FinishPreparedPublication(CompiledCode& Code, bool SourceStillValid) {
  // The caller has reacquired its invalidation guard and revalidated the
  // immutable revision, exact source thread and retained selected buffer.
  if (!SourceStillValid || !PearWriter || !*PearWriter || !PearPreparedBuffer ||
      CurrentCodeBuffer != PearPreparedBuffer || !Code.PearPendingEmission || Code.PearOwnerPublished ||
      Code.BlockBegin != PearPendingTemp || Code.Size != PearPendingSize || !Code.Size ||
      !FEXCore::Utils::PearFEXMemory::CurrentExecutor()) {
    LogMan::Msg::EFmt("Pear prepared source generation changed before publication");
    CancelUnchangedPreparedPublication(); return false;
  }
  const auto Source = reinterpret_cast<uintptr_t>(PearPendingTemp);
  for (const auto& Entry : Code.EntryPoints) {
    const auto Address = reinterpret_cast<uintptr_t>(Entry.second);
    if (Address < Source || Address-Source >= Code.Size || (Address & 3)) {
      LogMan::Msg::EFmt("Pear pending entrypoint is outside private NX emission");
      CancelUnchangedPreparedPublication(); return false;
    }
  }
  memcpy(PearWriter->Data(), PearPendingTemp, Code.Size);
  auto Published = PearWriter->Publish();
  if (!Published) {
    LogMan::Msg::EFmt("Pear source publication refused: status {}, domain {}, code {}",
                      Published.Status, Published.ErrorDomain, Published.ErrorCode);
    DiscardPreparedPublication(); return false;
  }
  if (!PearPreparedBuffer->ComparePearUpdate(PearBefore, PearTransaction)) {
    // Published bytes have no new lookup pointer. Do not fabricate a token or
    // recover by generic protection/allocation; the source must refuse/recover.
    LogMan::Msg::EFmt("Pear source token changed before lookup publication");
    FEXCore::Utils::PearFEXMemory::Retirement::PoisonSourceAdmission({PEAR_FEX_STALE_IDENTITY,0,0});
    DiscardPreparedPublication(); return false;
  }
  for (auto& Entry : Code.EntryPoints) {
    const auto Offset = reinterpret_cast<uintptr_t>(Entry.second)-Source;
    Entry.second = PearPreparedDestination+Offset;
  }
  Code.BlockBegin = PearPreparedDestination;
  Code.HostCodeOffset = reinterpret_cast<uintptr_t>(Code.BlockBegin)-
                        reinterpret_cast<uintptr_t>(PearPreparedBuffer->GetBufferBase());
  Code.PearPendingEmission = false; Code.PearOwnerPublished = true;
  DiscardPreparedPublication(); return true;
}
void Arm64JITCore::CancelUnchangedPreparedPublication() {
  // Called only before the first copy into the admitted write window. Existing
  // published bytes are unchanged: restore RX with checked cache maintenance,
  // but publish no candidate entrypoint. Abort is valid only for virgin NONE.
  if (PearWriter && *PearWriter && PearPreparedBuffer &&
      PearBefore.Token.expected_state==PEAR_FEX_PUBLISHED_RX) {
    const auto Restored=PearWriter->Publish();
    const bool Updated=Restored && PearPreparedBuffer->ComparePearUpdate(PearBefore,PearTransaction);
    if (!Restored) FEXCore::Utils::PearFEXMemory::Retirement::PoisonSourceAdmission(Restored);
    else if (!Updated) FEXCore::Utils::PearFEXMemory::Retirement::PoisonSourceAdmission({PEAR_FEX_STALE_IDENTITY,0,0});
  }
  DiscardPreparedPublication();
}
void Arm64JITCore::DiscardPreparedPublication() {
  if (PearWriter && *PearWriter) {
    const auto Aborted = PearWriter->Abort();
    const bool Updated=PearPreparedBuffer && PearPreparedBuffer->ComparePearUpdate(PearBefore,PearTransaction);
    if (!Aborted) {
      FEXCore::Utils::PearFEXMemory::Retirement::PoisonSourceAdmission(Aborted);
      LogMan::Msg::EFmt("Pear source abort refused: status {}, domain {}, code {}",
                       Aborted.Status, Aborted.ErrorDomain, Aborted.ErrorCode);
    } else if (!Updated) {
      FEXCore::Utils::PearFEXMemory::Retirement::PoisonSourceAdmission({PEAR_FEX_STALE_IDENTITY,0,0});
    }
  }
  PearWriter.reset(); PearPreparedBuffer.reset(); PearPreparedDestination = nullptr;
  if (PearPendingTemp) TempCodeBufferAllocator.DelayedDisownBuffer();
  PearPendingTemp = nullptr; PearPendingSize = 0;
}
#endif

CPUBackend::CompiledCode Arm64JITCore::LoadCachedCode(std::span<const uint8_t> HostBytes) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Disk cache remains unavailable in the selected approved policy. Never
  // reinterpret an arbitrary cached byte span as an owner publication proof.
  LogMan::Msg::EFmt("Pear disk-cache code publication is unavailable");
  return {};
#else
  // we stored it aligned, better still be?
  LOGMAN_THROW_A_FMT(HostBytes.size() % 16 == 0, "Needs to be 16B aligned!");
  auto AllocatedInfo = AllocateCodeBufferInSharedCache(HostBytes.size());

  uint8_t* Dest = AllocatedInfo.BufferAllocationOffset;
  memcpy(Dest, HostBytes.data(), HostBytes.size());
  ClearICache(Dest, HostBytes.size());

  CPUBackend::CompiledCode Result;
  Result.BlockBegin = Dest;
  Result.Size = HostBytes.size();
  Result.HostCodeOffset = Dest - CurrentCodeBuffer->GetBufferBase();
  return Result;
#endif
}

void Arm64JITCore::ResetStack() {
  if (SpillSlots == 0) {
    return;
  }

  const auto TotalSpillSlotsSize = SpillSlots * MaxSpillSlotSize;

  if (ARMEmitter::IsImmAddSub(TotalSpillSlotsSize)) {
    add(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::rsp, ARMEmitter::Reg::rsp, TotalSpillSlotsSize);
  } else {
    // Too big to fit in a 12bit immediate
    LoadConstant(ARMEmitter::Size::i64Bit, TMP1, TotalSpillSlotsSize);
    add(ARMEmitter::Size::i64Bit, ARMEmitter::XReg::rsp, ARMEmitter::XReg::rsp, TMP1, ARMEmitter::ExtendedType::LSL_64, 0);
  }
}

fextl::unique_ptr<CPUBackend> CreateArm64JITCore(FEXCore::Context::ContextImpl* ctx, FEXCore::Core::InternalThreadState* Thread) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // No implicit executable construction without the actual source gate's
  // retained initial allocation. Selected Pear callers use the typed path.
  return {};
#else
  return fextl::make_unique<Arm64JITCore>(ctx, Thread);
#endif
}
#ifdef PEAR_FEX_MEMORY_OWNER
fextl::unique_ptr<CPUBackend> CreatePearArm64JITCore(FEXCore::Context::ContextImpl* CTX,
    FEXCore::Core::InternalThreadState* Thread, fextl::shared_ptr<CodeBuffer> InitialBuffer) {
  return FEXCore::Allocator::TryMakePearMetadataObject<Arm64JITCore>(CTX, Thread, std::move(InitialBuffer));
}
#endif

} // namespace FEXCore::CPU
