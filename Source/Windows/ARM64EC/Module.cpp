#include "PearSlotLifetime.h"
#ifdef PEAR_PHASE_OBSERVE
#include "PearPhaseObservation.h"
#include <cstring>
static std::atomic<uint64_t> PearPhaseLife {};
static void PearPhaseMap(uint64_t,const char*);
static void PearPhaseUnmap(uint64_t,uint64_t);
#endif
#include <cerrno>
#include <cstdlib>
#ifdef PEAR_FEX_DARWIN
#include "Common/DarwinConfigPolicy.h"
#endif
// SPDX-License-Identifier: MIT
/*
$info$
tags: Bin|ARM64EC
desc: Implements the ARM64EC BT module API using FEXCore
$end_info$
*/

#include <FEXCore/fextl/fmt.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/Context.h>
#ifdef PEAR_FEX_MEMORY_OWNER
#include <FEXCore/Utils/PearFEXMemory.h>
#include <atomic>
#include <mutex>
#endif
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/DiskCacheFileMapper.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Config/Config.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/Threads.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/Utils/SHMStats.h>
#include <FEXCore/Utils/EnumOperators.h>
#include <FEXCore/Utils/EnumUtils.h>
#include <FEXCore/Utils/FPState.h>
#include <FEXCore/Utils/ArchHelpers/Arm64.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/Utils/SignalScopeGuards.h>

#include "Windows/Common/Allocator.h"
#include "Windows/Common/EnvironmentVariablesHandling.h"
#include "Windows/Common/FEXUnixLib.h"
#include "Common/CallRetStack.h"
#include "Common/JITGuardPage.h"
#include "Common/Config.h"
#include "Common/Exception.h"
#include "Common/ImageTracker.h"
#include "Common/InvalidationTracker.h"
#include "Common/Threads.h"
#include "Common/OvercommitTracker.h"
#include "Common/TSOHandlerConfig.h"
#include "Common/CPUFeatures.h"
#include "Common/Logging.h"
#include "Common/Module.h"
#include "Common/CRT/CRT.h"
#include "Common/PortabilityInfo.h"
#include "Common/Handle.h"
#include "DummyHandlers.h"
#include "BTInterface.h"
#include "Windows/Common/SHMStats.h"

#include <cstdint>
#include <cstdio>
#include <type_traits>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <utility>
#include <ntstatus.h>
#include <windef.h>
#include <winternl.h>
#include <winnt.h>
#include <wine/debug.h>

namespace Exception {
class ECSyscallHandler;
}
static void PearInitCheckpoint(const char*, uint32_t, uint32_t = 0, int32_t = 0);

extern "C" {
extern IMAGE_DOS_HEADER __ImageBase; // Provided by the linker

extern void* ExitFunctionEC;
extern void* CheckCall;
extern void* ExitFunctionSuspendPoint;
extern void* ExitFunctionSuspendResumePoint;

void* X64ReturnInstr; // See Module.S
uintptr_t NtDllBase;

// Exports on ARM64EC point to x64 fast forward sequences to allow for redirecting to the JIT if functions are hotpatched. This LUT is from their addresses to the relative addresses of the native code exports.
uint32_t* NtDllRedirectionLUT;
uint32_t NtDllRedirectionLUTSize;

// Wine doesn't support issuing direct system calls with SVC, and unlike Windows it doesn't have a 'stable' syscall number for NtContinue
void* WineSyscallDispatcher;
uint64_t WineNtContinueSyscallId;
uint64_t WineNtAllocateVirtualMemorySyscallId;
uint64_t WineNtProtectVirtualMemorySyscallId;
uint64_t WineNtRaiseExceptionSyscallId;

NTSTATUS NtContinueNative(ARM64_NT_CONTEXT* NativeContext, BOOLEAN Alert);
NTSTATUS NtAllocateVirtualMemoryNative(HANDLE, PVOID*, ULONG_PTR, SIZE_T*, ULONG, ULONG);
NTSTATUS NtProtectVirtualMemoryNative(HANDLE, PVOID*, SIZE_T*, ULONG, ULONG*);
NTSTATUS NtRaiseExceptionNative(EXCEPTION_RECORD*, ARM64_NT_CONTEXT*, BOOL);
static fextl::string AppConfigName {};

[[noreturn]]
void JumpSetStack(uintptr_t PC, uintptr_t SP);
}

struct ThreadCPUArea {
  static constexpr size_t TEBCPUAreaOffset = 0x1788;
  CHPE_V2_CPU_AREA_INFO* Area;

  explicit ThreadCPUArea(_TEB* TEB)
    : Area(*reinterpret_cast<CHPE_V2_CPU_AREA_INFO**>(reinterpret_cast<uintptr_t>(TEB) + TEBCPUAreaOffset)) {}

  uint64_t& EmulatorStackLimit() const {
    return Area->EmulatorStackLimit;
  }

  uint64_t& EmulatorStackBase() const {
    return Area->EmulatorStackBase;
  }

  ARM64EC_NT_CONTEXT& ContextAmd64() const {
    return *Area->ContextAmd64;
  }

  FEXCore::Core::CpuStateFrame*& StateFrame() const {
    return reinterpret_cast<FEXCore::Core::CpuStateFrame*&>(Area->EmulatorData[0]);
  }

  FEXCore::Core::InternalThreadState*& ThreadState() const {
    return reinterpret_cast<FEXCore::Core::InternalThreadState*&>(Area->EmulatorData[1]);
  }

  uint64_t& DispatcherLoopTopEnterEC() const {
    return reinterpret_cast<uint64_t&>(Area->EmulatorData[2]);
  }

  uint64_t& DispatcherLoopTopEnterECFillSRA() const {
    return reinterpret_cast<uint64_t&>(Area->EmulatorData[3]);
  }
};

struct FrontendThreadData {
#ifdef PEAR_PHASE_OBSERVE
  uint64_t PhaseLifetime {PearPhaseLife.fetch_add(1,std::memory_order_relaxed)+1};
#endif
  bool InLockedRWXRead {};
#ifdef PEAR_FEX_MEMORY_OWNER
  std::optional<FEXCore::Utils::PearFEXMemory::SourceLifetime> MemoryNotificationLife;
  unsigned MemoryNotificationKind {};
  uint64_t MemoryNotificationStart {}, MemoryNotificationSize {};
#endif
};

namespace {
#ifdef PEAR_FEX_MEMORY_OWNER
FEXCore::Context::PearContextOwner CTX;
#else
fextl::unique_ptr<FEXCore::Context::Context> CTX;
#endif
fextl::unique_ptr<FEX::DummyHandlers::DummySignalDelegator> SignalDelegator;
fextl::unique_ptr<Exception::ECSyscallHandler> SyscallHandler;
fextl::unique_ptr<FEX::Windows::StatAlloc> StatAllocHandler;
std::optional<FEX::Windows::InvalidationTracker> InvalidationTracker;
std::optional<FEX::Windows::CPUFeatures> CPUFeatures;
std::optional<FEX::Windows::OvercommitTracker> OvercommitTracker;
std::optional<FEX::Windows::ImageTracker> ImageTracker;

std::recursive_mutex ThreadCreationMutex;
// Map of TIDs to their FEX thread state, `ThreadCreationMutex` must be locked when accessing
std::unordered_map<DWORD, FEXCore::Core::InternalThreadState*> Threads;

#ifdef PEAR_FEX_MEMORY_OWNER
namespace PearMemory = FEXCore::Utils::PearFEXMemory;
std::atomic<bool> PearSourceReady {false};
std::atomic<NTSTATUS> PearSourceStatus {STATUS_NOT_SUPPORTED};
static_assert(std::atomic<NTSTATUS>::is_always_lock_free, "Raw refusal status must not acquire a hidden lock");
// Actual bridge/source-construction results retain their native error domain.
// These private records are not exports and do not assert runtime admission.
std::mutex PearOutcomeMutex;
PearMemory::Result PearPrimaryOutcome {};
PearMemory::Result PearCleanupOutcome {};
bool PearHasPrimaryOutcome {};
bool PearHasCleanupOutcome {};
void PearRecordPrimary(PearMemory::Result Outcome) {
  std::scoped_lock Lock(PearOutcomeMutex);
  if (!PearHasPrimaryOutcome) { PearPrimaryOutcome = Outcome; PearHasPrimaryOutcome = true; }
}
void PearRecordCleanup(PearMemory::Result Outcome) {
  std::scoped_lock Lock(PearOutcomeMutex);
  if (!PearHasCleanupOutcome || PearCleanupOutcome) {
    PearCleanupOutcome = Outcome; PearHasCleanupOutcome = true;
  }
}
NTSTATUS PearFailureStatus(const PearMemory::Result& Outcome) {
  // Only a real signed NTSTATUS domain is forwarded as the source NTSTATUS.
  // Other native domains stay intact in the private Result, not reinterpreted.
  return Outcome.ErrorDomain == PEAR_FEX_ERROR_NTSTATUS && Outcome.ErrorCode ?
    static_cast<NTSTATUS>(Outcome.ErrorCode) : STATUS_NOT_SUPPORTED;
}
// One bounded in-progress slot per actual TID prevents owner-wait reentry from
// constructing an additional source ThreadState before final publication.
DWORD PearPendingTIDs[64] {};
static_assert(sizeof(PearPendingTIDs) == 256, "Bounded Module pending NX ledger");
inline constexpr size_t PearModuleNXMetadataBytes = sizeof(PearPendingTIDs) +
  sizeof(PearSourceReady) + sizeof(PearSourceStatus) + sizeof(PearOutcomeMutex) +
  sizeof(PearPrimaryOutcome) + sizeof(PearCleanupOutcome) +
  sizeof(PearHasPrimaryOutcome) + sizeof(PearHasCleanupOutcome);
static_assert(PearModuleNXMetadataBytes <= 1024, "Module ledger enters aggregate NX accounting");
class PearThreadPreparation {
public:
  PearThreadPreparation() : TID(GetCurrentThreadId()) {
    std::scoped_lock Lock(ThreadCreationMutex);
    if (!TID || Threads.contains(TID)) return;
    DWORD* Empty {};
    for (auto& Pending : PearPendingTIDs) {
      if (Pending == TID) return;
      if (!Pending && !Empty) Empty = &Pending;
    }
    if (!Empty) { Failure = STATUS_NO_MEMORY; return; }
    *Empty = TID; Owned = true;
  }
  ~PearThreadPreparation() {
    if (!Owned) return;
    // A constructor/ordinary metadata exception preserves the original
    // exception. It cannot leave mandatory followups treating setup as ready.
    if (!Committed) PearSourceReady.store(false, std::memory_order_release);
    std::scoped_lock Lock(ThreadCreationMutex);
    for (auto& Pending : PearPendingTIDs) if (Pending == TID) { Pending = 0; break; }
  }
  void Commit() { Committed = true; }
  explicit operator bool() const { return Owned; }
  DWORD ID() const { return TID; }
  NTSTATUS Status() const { return Failure; }
private:
  DWORD TID {};
  NTSTATUS Failure {STATUS_NOT_SUPPORTED};
  bool Owned {};
  bool Committed {};
};
#endif


std::pair<NTSTATUS, ThreadCPUArea> GetThreadCPUArea(HANDLE Thread) {
  THREAD_BASIC_INFORMATION Info;
  const NTSTATUS Err = NtQueryInformationThread(Thread, ThreadBasicInformation, &Info, sizeof(Info), nullptr);
  return {Err, ThreadCPUArea(reinterpret_cast<_TEB*>(Info.TebBaseAddress))};
}

ThreadCPUArea GetCPUArea() {
  return ThreadCPUArea(NtCurrentTeb());
}

class ScopedCallbackDisable {
private:
  bool Prev;

public:
  ScopedCallbackDisable() {
    const auto CPUArea = GetCPUArea();
    Prev = CPUArea.Area->InSyscallCallback;
    CPUArea.Area->InSyscallCallback = true;
  }

  ~ScopedCallbackDisable() {
    GetCPUArea().Area->InSyscallCallback = Prev;
  }
};


FrontendThreadData* GetFrontendThreadData(FEXCore::Core::InternalThreadState* Thread) {
  return static_cast<FrontendThreadData*>(Thread->FrontendPtr);
}

bool IsEmulatorStackAddress(const ThreadCPUArea CPUArea, uint64_t Address) {
  return Address <= CPUArea.EmulatorStackBase() && Address >= CPUArea.EmulatorStackLimit();
}

bool IsDispatcherAddress(uint64_t Address) {
  const auto& Config = SignalDelegator->GetConfig();
  return Address >= Config.DispatcherBegin && Address < Config.DispatcherEnd;
}


void FillNtDllLUTs(HMODULE NtDll) {
  ULONG Size;
  const auto* LoadConfig =
    reinterpret_cast<_IMAGE_LOAD_CONFIG_DIRECTORY64*>(RtlImageDirectoryEntryToData(NtDll, true, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &Size));
  const auto* CHPEMetadata = reinterpret_cast<IMAGE_ARM64EC_METADATA*>(LoadConfig->CHPEMetadataPointer);
  const auto* RedirectionTableBegin = reinterpret_cast<IMAGE_ARM64EC_REDIRECTION_ENTRY*>(NtDllBase + CHPEMetadata->RedirectionMetadata);
  const auto* RedirectionTableEnd = RedirectionTableBegin + CHPEMetadata->RedirectionMetadataCount;

  NtDllRedirectionLUTSize = std::prev(RedirectionTableEnd)->Source + 1;

  SIZE_T AllocSize = NtDllRedirectionLUTSize * sizeof(uint32_t);
  NtAllocateVirtualMemoryNative(NtCurrentProcess(), reinterpret_cast<void**>(&NtDllRedirectionLUT), 0, &AllocSize, MEM_COMMIT | MEM_RESERVE,
                                PAGE_READWRITE);
  for (auto It = RedirectionTableBegin; It != RedirectionTableEnd; It++) {
    NtDllRedirectionLUT[It->Source] = It->Destination;
  }
}

template<typename T>
void WriteModuleRVA(HMODULE Module, LONG RVA, T Data) {
  if (!RVA) {
    return;
  }

  void* Address = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(Module) + RVA);
  void* ProtAddress = Address;
  SIZE_T ProtSize = sizeof(T);
  ULONG Prot;
  NtProtectVirtualMemoryNative(NtCurrentProcess(), &ProtAddress, &ProtSize, PAGE_READWRITE, &Prot);
  *reinterpret_cast<T*>(Address) = Data;
  NtProtectVirtualMemoryNative(NtCurrentProcess(), &ProtAddress, &ProtSize, Prot, nullptr);
}

void PatchCallChecker() {
  // See the comment for CheckCall in Module.S for why this is necessary
  const auto Module = reinterpret_cast<HMODULE>(&__ImageBase);
  ULONG Size;
  const auto* LoadConfig =
    reinterpret_cast<_IMAGE_LOAD_CONFIG_DIRECTORY64*>(RtlImageDirectoryEntryToData(Module, true, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &Size));
  const auto* CHPEMetadata = reinterpret_cast<IMAGE_ARM64EC_METADATA*>(LoadConfig->CHPEMetadataPointer);
  WriteModuleRVA(Module, CHPEMetadata->__os_arm64x_dispatch_call, &CheckCall);
  WriteModuleRVA(Module, CHPEMetadata->__os_arm64x_dispatch_icall, &CheckCall);
  WriteModuleRVA(Module, CHPEMetadata->__os_arm64x_dispatch_icall_cfg, &CheckCall);
}

// Fills in the syscall numbers necessary to call *Native variants of syscalls from FEX under wine.
void ParseWineSyscallNumbers(HMODULE NtDll) {
  ULONG Size;
  const auto* Exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(RtlImageDirectoryEntryToData(NtDll, true, IMAGE_DIRECTORY_ENTRY_EXPORT, &Size));
  const auto* NameTable = reinterpret_cast<uint32_t*>(NtDllBase + Exports->AddressOfNames);
  const auto* FunctionTable = reinterpret_cast<uint32_t*>(NtDllBase + Exports->AddressOfFunctions);
  const auto* OrdinalTable = reinterpret_cast<uint16_t*>(NtDllBase + Exports->AddressOfNameOrdinals);
  struct SyscallEntry {
    const char* Name;
    uint32_t RVA;

    bool operator<(const SyscallEntry& Other) const {
      return RVA < Other.RVA;
    }
  };

  // Cannot use any syscalls at this stage, so rely on a stack-allocated array
  std::array<SyscallEntry, 0x200> SyscallTable;
  auto SyscallTableEnd = SyscallTable.begin();

  // Windows/Wine orders syscalls in memory by their ID, take advantage of that to find the syscall indices for those
  // which we need to manually issue. Note that all functions starting with Nt besides NtGetTickCount are syscalls.
  for (uint32_t Idx = 0; Idx < Exports->NumberOfNames; Idx++) {
    const char* Name = reinterpret_cast<const char*>(NtDllBase + NameTable[Idx]);
    if (Name[0] == 'N' && Name[1] == 't' && strcmp(Name, "NtGetTickCount") != 0) {
      *SyscallTableEnd++ = {Name, FunctionTable[OrdinalTable[Idx]]};
    }
  }

  // Sort such that index 0 is now syscall 0, etc
  std::sort(SyscallTable.begin(), SyscallTableEnd);

  for (auto it = SyscallTable.begin(); it != SyscallTableEnd; it++) {
    uint32_t CurSyscallId = static_cast<uint32_t>(std::distance(SyscallTable.begin(), it));
    if (strcmp(it->Name, "NtContinue") == 0) {
      WineNtContinueSyscallId = CurSyscallId;
    } else if (strcmp(it->Name, "NtAllocateVirtualMemory") == 0) {
      WineNtAllocateVirtualMemorySyscallId = CurSyscallId;
    } else if (strcmp(it->Name, "NtProtectVirtualMemory") == 0) {
      WineNtProtectVirtualMemorySyscallId = CurSyscallId;
    } else if (strcmp(it->Name, "NtRaiseException") == 0) {
      WineNtRaiseExceptionSyscallId = CurSyscallId;
    }
  }
}

// Syscall thunks may have been patched before FEX has loaded, the default call checker installed by ntdll into FEX will
// try to invoke the JIT when calling such patched syscalls but this obviously doesn't work before FEX is initalised.
// This function parses ntdll and sets up a custom call checker to prevent this, as such it must avoid using any syscall
// thunks itself.
void InitSyscalls() {
  // The ntdll exports called by GetModuleHandle/GetProcAddress aren't known to be patched before JIT init by any current
  // software so are safe to call, but if that changes the loader structures in the PEB could be parsed manually.
  const auto NtDll = GetModuleHandleW(L"ntdll.dll");
  NtDllBase = reinterpret_cast<uintptr_t>(NtDll);

  const auto WineSyscallDispatcherPtr = reinterpret_cast<void**>(GetProcAddress(NtDll, "__wine_syscall_dispatcher"));
  if (WineSyscallDispatcherPtr) {
    WineSyscallDispatcher = *WineSyscallDispatcherPtr;
    ParseWineSyscallNumbers(NtDll);
  }

  FillNtDllLUTs(NtDll);
  PatchCallChecker();
}

void HandleImageMap(uint64_t Address, bool MainImage = false) {
  fextl::string ModulePath = FEX::Windows::GetSectionFilePath(Address);
  fextl::string ModuleName = fextl::string {FEX::Windows::BaseName(ModulePath)};
  InvalidationTracker->HandleImageMap(ModuleName, Address);
  ImageTracker->HandleImageMap(ModulePath, Address, MainImage);
#ifdef PEAR_PHASE_OBSERVE
  PearPhaseMap(Address,ModuleName.c_str());
#endif
}

void HandleImageUnmap(uint64_t Address, uint64_t Size) {
  ImageTracker->HandleImageUnmap(Address, Size);
#ifdef PEAR_PHASE_OBSERVE
  PearPhaseUnmap(Address,Size);
#endif
}
} // namespace

namespace Exception {
static std::optional<FEX::Windows::TSOHandlerConfig> HandlerConfig;
static uintptr_t KiUserExceptionDispatcher;

struct alignas(16) KiUserExceptionDispatcherStackLayout {
  ARM64_NT_CONTEXT Context;
  uint64_t Pad[4]; // Only present on newer Windows versions, likely for SVE.
  EXCEPTION_RECORD Rec;
  uint64_t Align;
  uint64_t Redzone[2];
};

static bool HandleUnalignedAccess(const ThreadCPUArea CPUArea, ARM64_NT_CONTEXT& Context, bool IsJIT) {
  auto Thread = CPUArea.ThreadState();
  FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedSIGBUSCount, 1);
  const auto Result =
    FEXCore::ArchHelpers::Arm64::HandleUnalignedAccess(Thread, HandlerConfig->GetUnalignedHandlerType(), Context.Pc, &Context.X0, IsJIT);
  Context.Pc += Result.value_or(0);
  return Result.has_value();
}

static void LoadStateFromECContext(FEXCore::Core::InternalThreadState* Thread, CONTEXT& Context) {
  auto& State = Thread->CurrentFrame->State;

  if ((Context.ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER) {
    // General register state
    State.gregs[FEXCore::X86State::REG_RAX] = Context.Rax;
    State.gregs[FEXCore::X86State::REG_RCX] = Context.Rcx;
    State.gregs[FEXCore::X86State::REG_RDX] = Context.Rdx;
    State.gregs[FEXCore::X86State::REG_RBX] = Context.Rbx;

    State.gregs[FEXCore::X86State::REG_RSI] = Context.Rsi;
    State.gregs[FEXCore::X86State::REG_RDI] = Context.Rdi;
    State.gregs[FEXCore::X86State::REG_R8] = Context.R8;
    State.gregs[FEXCore::X86State::REG_R9] = Context.R9;
    State.gregs[FEXCore::X86State::REG_R10] = Context.R10;
    State.gregs[FEXCore::X86State::REG_R11] = Context.R11;
    State.gregs[FEXCore::X86State::REG_R12] = Context.R12;
    State.gregs[FEXCore::X86State::REG_R13] = Context.R13;
    State.gregs[FEXCore::X86State::REG_R14] = Context.R14;
    State.gregs[FEXCore::X86State::REG_R15] = Context.R15;
  }

  if ((Context.ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL) {
    State.rip = Context.Rip;
    State.gregs[FEXCore::X86State::REG_RSP] = Context.Rsp;
    State.gregs[FEXCore::X86State::REG_RBP] = Context.Rbp;
    CTX->SetFlagsFromCompactedEFLAGS(Thread, Context.EFlags);
  }

  if ((Context.ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS) {
    State.es_idx = Context.SegEs & 0xffff;
    State.cs_idx = Context.SegCs & 0xffff;
    State.ss_idx = Context.SegSs & 0xffff;
    State.ds_idx = Context.SegDs & 0xffff;
    State.fs_idx = Context.SegFs & 0xffff;
    State.gs_idx = Context.SegGs & 0xffff;

    // The TEB is the only populated GDT entry by default
    const auto TEB = reinterpret_cast<uint64_t>(NtCurrentTeb());
    auto GDT = State.GetSegmentFromIndex(State, (Context.SegGs & 0xffff));
    State.SetGDTBase(GDT, TEB);
    State.SetGDTLimit(GDT, 0xF'FFFFU);
    State.gs_cached = TEB;
    State.fs_cached = 0;
    State.es_cached = 0;
    State.cs_cached = 0;
    State.ss_cached = 0;
    State.ds_cached = 0;
  }

  if ((Context.ContextFlags & CONTEXT_FLOATING_POINT) == CONTEXT_FLOATING_POINT) {
    // Floating-point register state
    if ((Context.ContextFlags & CONTEXT_XSTATE) == CONTEXT_XSTATE) {
      const auto* Ymm = RtlLocateExtendedFeature(reinterpret_cast<CONTEXT_EX*>(&Context + 1), XSTATE_AVX, nullptr);
      CTX->SetXMMRegistersFromState(Thread, reinterpret_cast<const __uint128_t*>(Context.FltSave.XmmRegisters),
                                    reinterpret_cast<const __uint128_t*>(Ymm));
    } else {
      CTX->SetXMMRegistersFromState(Thread, reinterpret_cast<const __uint128_t*>(Context.FltSave.XmmRegisters), nullptr);
    }
    memcpy(State.mm, Context.FltSave.FloatRegisters, sizeof(State.mm));

    State.FCW = Context.FltSave.ControlWord;
    State.flags[FEXCore::X86State::X87FLAG_IE_LOC] = Context.FltSave.StatusWord & 1;
    State.flags[FEXCore::X86State::X87FLAG_C0_LOC] = (Context.FltSave.StatusWord >> 8) & 1;
    State.flags[FEXCore::X86State::X87FLAG_C1_LOC] = (Context.FltSave.StatusWord >> 9) & 1;
    State.flags[FEXCore::X86State::X87FLAG_C2_LOC] = (Context.FltSave.StatusWord >> 10) & 1;
    State.flags[FEXCore::X86State::X87FLAG_C3_LOC] = (Context.FltSave.StatusWord >> 14) & 1;
    State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] = (Context.FltSave.StatusWord >> 11) & 0b111;
    State.AbridgedFTW = Context.FltSave.TagWord;
  }
}

static void ReconstructThreadState(FEXCore::Core::InternalThreadState* Thread, ARM64_NT_CONTEXT& Context) {
  const auto& Config = SignalDelegator->GetConfig();
  auto& State = Thread->CurrentFrame->State;

  State.rip = CTX->RestoreRIPFromHostPC(Thread, Context.Pc);

  // Spill all SRA GPRs
  for (size_t i = 0; i < Config.SRAGPRCount; i++) {
    State.gregs[i] = Context.X[Config.SRAGPRMapping[i]];
  }

  // Spill all SRA FPRs
  for (size_t i = 0; i < Config.SRAFPRCount; i++) {
    memcpy(State.xmm.sse.data[i], &Context.V[Config.SRAFPRMapping[i]], sizeof(__uint128_t));
  }

  // Spill EFlags
  uint32_t EFlags = CTX->ReconstructCompactedEFLAGS(Thread, true, Context.X, Context.Cpsr);
  CTX->SetFlagsFromCompactedEFLAGS(Thread, EFlags);
}

// Reconstructs an x64 context from the input thread's state, packed into a regular ARM64 context following the ARM64EC register mapping
static ARM64_NT_CONTEXT StoreStateToPackedECContext(FEXCore::Core::InternalThreadState* Thread, uint32_t FPCR, uint32_t FPSR) {
  ARM64_NT_CONTEXT ECContext {};

  ECContext.ContextFlags = CONTEXT_ARM64_FULL;
  if (CPUFeatures->IsFeaturePresent(PF_AVX2_INSTRUCTIONS_AVAILABLE)) {
    // This is a FEX extension and requires corresponding wine-side patches to be of use, however it is harmless to set
    // even if those patches are not used.
    ECContext.ContextFlags |= CONTEXT_ARM64_FEX_YMMSTATE;
  }

  auto& State = Thread->CurrentFrame->State;

  ECContext.X8 = State.gregs[FEXCore::X86State::REG_RAX];
  ECContext.X0 = State.gregs[FEXCore::X86State::REG_RCX];
  ECContext.X1 = State.gregs[FEXCore::X86State::REG_RDX];
  ECContext.X27 = State.gregs[FEXCore::X86State::REG_RBX];
  ECContext.Sp = State.gregs[FEXCore::X86State::REG_RSP];
  ECContext.Fp = State.gregs[FEXCore::X86State::REG_RBP];
  ECContext.X25 = State.gregs[FEXCore::X86State::REG_RSI];
  ECContext.X26 = State.gregs[FEXCore::X86State::REG_RDI];
  ECContext.X2 = State.gregs[FEXCore::X86State::REG_R8];
  ECContext.X3 = State.gregs[FEXCore::X86State::REG_R9];
  ECContext.X4 = State.gregs[FEXCore::X86State::REG_R10];
  ECContext.X5 = State.gregs[FEXCore::X86State::REG_R11];
  ECContext.X19 = State.gregs[FEXCore::X86State::REG_R12];
  ECContext.X20 = State.gregs[FEXCore::X86State::REG_R13];
  ECContext.X21 = State.gregs[FEXCore::X86State::REG_R14];
  ECContext.X22 = State.gregs[FEXCore::X86State::REG_R15];

  ECContext.Pc = State.rip;

  CTX->ReconstructXMMRegisters(Thread, reinterpret_cast<__uint128_t*>(&ECContext.V[0]), reinterpret_cast<__uint128_t*>(&ECContext.V[16]));

  ECContext.Lr = State.mm[0][0];
  ECContext.X6 = State.mm[1][0];
  ECContext.X7 = State.mm[2][0];
  ECContext.X9 = State.mm[3][0];
  ECContext.X16 = (State.mm[3][1] & 0xffff) << 48 | (State.mm[2][1] & 0xffff) << 32 | (State.mm[1][1] & 0xffff) << 16 | (State.mm[0][1] & 0xffff);
  ECContext.X10 = State.mm[4][0];
  ECContext.X11 = State.mm[5][0];
  ECContext.X12 = State.mm[6][0];
  ECContext.X15 = State.mm[7][0];
  ECContext.X17 = (State.mm[7][1] & 0xffff) << 48 | (State.mm[6][1] & 0xffff) << 32 | (State.mm[5][1] & 0xffff) << 16 | (State.mm[4][1] & 0xffff);

  // Zero all disallowed registers
  ECContext.X13 = 0;
  ECContext.X14 = 0;
  ECContext.X18 = 0;
  ECContext.X23 = 0;
  ECContext.X24 = 0;
  ECContext.X28 = 0;

  // NZCV+SS will be converted into EFlags by ntdll, the rest are lost during exception handling.
  // See HandleGuestException
  uint32_t EFlags = CTX->ReconstructCompactedEFLAGS(Thread, false, nullptr, 0);
  ECContext.Cpsr = 0;
  ECContext.Cpsr |= (EFlags & (1U << FEXCore::X86State::RFLAG_TF_RAW_LOC)) ? (1U << 21) : 0;
  ECContext.Cpsr |= (EFlags & (1U << FEXCore::X86State::RFLAG_OF_RAW_LOC)) ? (1U << 28) : 0;
  ECContext.Cpsr |= (EFlags & (1U << FEXCore::X86State::RFLAG_CF_RAW_LOC)) ? (1U << 29) : 0;
  ECContext.Cpsr |= (EFlags & (1U << FEXCore::X86State::RFLAG_ZF_RAW_LOC)) ? (1U << 30) : 0;
  ECContext.Cpsr |= (EFlags & (1U << FEXCore::X86State::RFLAG_SF_RAW_LOC)) ? (1U << 31) : 0;

  ECContext.Fpcr = FPCR;
  ECContext.Fpsr = FPSR;

  return ECContext;
}

static void RethrowGuestException(const EXCEPTION_RECORD& Rec, ARM64_NT_CONTEXT& Context) {
  auto* Thread = GetCPUArea().ThreadState();
  auto& Fault = Thread->CurrentFrame->SynchronousFaultData;

  LogMan::Msg::DFmt("Reconstructing context");
  if (!IsDispatcherAddress(Context.Pc)) {
    ReconstructThreadState(Thread, Context);
  }
  ARM64_NT_CONTEXT GuestContext = StoreStateToPackedECContext(Thread, Context.Fpcr, Context.Fpsr);
  LogMan::Msg::DFmt("pc: {:X} rip: {:X}", Context.Pc, GuestContext.Pc);

  // X64 Windows always clears TF, DF and AF when handling an exception, restoring after.
  // Current ARM64EC windows can only restore NZCV+SS when returning from an exception and other flags are left untouched from the handler context.
  // TODO: Can extend wine to support this by mapping the remaining EFlags into reserved cpsr members.
  uint32_t EFlags = CTX->ReconstructCompactedEFLAGS(Thread, false, nullptr, 0);
  EFlags &= ~(1 << FEXCore::X86State::RFLAG_TF_RAW_LOC);
  CTX->SetFlagsFromCompactedEFLAGS(Thread, EFlags);

  BOOL FirstChance = TRUE;
  EXCEPTION_RECORD GuestRec = FEX::Windows::HandleGuestException(Fault, Rec, GuestContext.Pc, GuestContext.X8, GuestContext.X0, FirstChance);
  if (GuestRec.ExceptionCode == EXCEPTION_SINGLE_STEP) {
    GuestContext.Cpsr &= ~(1 << 21); // PSTATE.SS
  } else if (GuestRec.ExceptionCode == EXCEPTION_BREAKPOINT) {
    // INT3 will set RIP to the instruction following it, undo this (any edge cases with multibyte instructions that trigger breakpoints are bugs present in Windows also)
    GuestContext.Pc -= 1;
  }

  NtRaiseExceptionNative(&GuestRec, &GuestContext, FirstChance);
}

class ECSyscallHandler : public FEXCore::HLE::SyscallHandler, public FEXCore::Allocator::FEXAllocOperators {
public:
  ECSyscallHandler() = default;

  void HandleSyscall(FEXCore::Core::CpuStateFrame* Frame) override {
    ProcessPendingCrossProcessEmulatorWork();

    // Manually raise an exeption with the current JIT state packed into a native context, ntdll handles this and
    // reenters the JIT (see dlls/ntdll/signal_arm64ec.c in wine).
    uint64_t FPCR, FPSR;
    __asm volatile("mrs %[fpcr], fpcr" : [fpcr] "=r"(FPCR));
    __asm volatile("mrs %[fpsr], fpsr" : [fpsr] "=r"(FPSR));

    auto* Thread = GetCPUArea().ThreadState();
    KiUserExceptionDispatcherStackLayout DispatchArgs {
      .Context = StoreStateToPackedECContext(Thread, static_cast<uint32_t>(FPCR), static_cast<uint32_t>(FPSR)),
      .Rec = {.ExceptionCode = STATUS_EMULATION_SYSCALL}};
    // PC is expected to hold the return address after the thunk, so skip over the INT 2E/SYSCALL instruction.
    DispatchArgs.Context.Pc += 2;
#ifdef PEAR_FEX_MEMORY_OWNER
    // Upstream's Windows syscall transfer abandons this native call frame and
    // resumes through BeginSimulation, not through the dispatcher return PC.
    // Release the actual global execution lease before that nonlocal transfer;
    // BeginSimulation must obtain a new checked lease after Wine redirects it.
    const auto Exited = CTX->ExitPearEC(Thread, true);
    PearInitCheckpoint("GuestSyscall.exit", Exited.Status, Exited.ErrorDomain, Exited.ErrorCode);
    PEAR_FEX_REQUIRE_RESULT(!!Exited, "Pear guest syscall handoff refused: status {}, domain {}, code {}", Exited);
    GetCPUArea().Area->InSimulation = false;
#endif
    JumpSetStack(KiUserExceptionDispatcher, reinterpret_cast<uintptr_t>(&DispatchArgs));
  }

  std::optional<FEXCore::ExecutableFileSectionInfo> LookupExecutableFileSection(FEXCore::Core::InternalThreadState*, uint64_t Address) override {
    return ImageTracker->LookupExecutableFileSection(Address);
  }

  void MarkGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) override {
    InvalidationTracker->ReprotectRWXIntervals(Start, Length);
  }

  void InvalidateGuestCodeRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) override {
    InvalidationTracker->InvalidateAlignedInterval(Start, Length, false);
  }

  void MarkOvercommitRange(uint64_t Start, uint64_t Length) override {
    OvercommitTracker->MarkRange(Start, Length);
  }

  void UnmarkOvercommitRange(uint64_t Start, uint64_t Length) override {
    OvercommitTracker->UnmarkRange(Start, Length);
  }

  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Address) override {
    return InvalidationTracker->QueryExecutableRange(Address);
  }

  void PreCompile() override {
    ProcessPendingCrossProcessEmulatorWork();
  }
};
} // namespace Exception

extern "C" void SyncThreadContext(CONTEXT* Context) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto Life = PearMemory::AcquireCurrentSourceLifetime(CTX.get());
  const auto CPUArea = GetCPUArea();
  PEAR_FEX_REQUIRE(Life && CTX && CPUArea.Area && Life.ActualThread() == CPUArea.ThreadState() &&
                   Context == &CPUArea.ContextAmd64().AMD64_Context,
                   "Pear EC context source identity unavailable");
#endif

  ProcessPendingCrossProcessEmulatorWork();
  auto* Thread = GetCPUArea().ThreadState();
  // All other EFlags bits are lost when converting to/from an ARM64EC context, so merge them in from the current JIT state.
  // This is advisable over dropping their values as thread suspend/resume uses this function, and that can happen at any point in guest code.
  static constexpr uint32_t ECValidEFlagsMask {(1U << FEXCore::X86State::RFLAG_OF_RAW_LOC) | (1U << FEXCore::X86State::RFLAG_CF_RAW_LOC) |
                                               (1U << FEXCore::X86State::RFLAG_ZF_RAW_LOC) | (1U << FEXCore::X86State::RFLAG_SF_RAW_LOC) |
                                               (1U << FEXCore::X86State::RFLAG_TF_RAW_LOC)};

  uint32_t StateEFlags = CTX->ReconstructCompactedEFLAGS(Thread, false, nullptr, 0);
  Context->EFlags = (Context->EFlags & ECValidEFlagsMask) | (StateEFlags & ~ECValidEFlagsMask);
  Exception::LoadStateFromECContext(Thread, *Context);
}


#ifdef PEAR_FEX_MEMORY_OWNER
static void PearCleanupPartialContext(NTSTATUS Status, const PearMemory::Result* Primary = nullptr) {
  PearSourceReady.store(false, std::memory_order_release);
  PearSourceStatus.store(Status, std::memory_order_release);
  if (Primary) PearRecordPrimary(*Primary);
  if (CTX) {
    const auto ActualPrimary = PearMemory::GetOriginalAttachFailure(CTX.get());
    if (ActualPrimary.Status != PEAR_FEX_UNAVAILABLE) PearRecordPrimary(ActualPrimary);
    if (PearMemory::CleanupWasAttempted(CTX.get()))
      PearRecordCleanup(PearMemory::GetCleanupOutcome(CTX.get()));
    // Core verifies the actual matching bootstrap/native-idle while Context
    // stays alive, detaches dispatcher/source buffers, drains retirement while
    // registered, and observes UNREGISTER before source-bound release proof.
    // Any refused/unknown step retains the actual Context and first failure.
    PearMemory::Result ConstructionCleanup {};
    const bool Cleaned = CTX->PreparePearConstructionCleanup(ConstructionCleanup);
    PearRecordCleanup(ConstructionCleanup);
    if (!Cleaned || !ConstructionCleanup || !PearMemory::SourceContextCanRelease(CTX.get())) return;
  }
  Exception::HandlerConfig.reset();
  CPUFeatures.reset(); ImageTracker.reset(); InvalidationTracker.reset();
  CTX.reset();
}
#endif

// Resolved before source admission; exception checkpoints must not acquire
// the loader lock to rediscover an already loaded debug-output export.
using PearCheckpointOutput = int (*)(const char*);
static std::atomic<PearCheckpointOutput> PearCheckpointSink {};
static_assert(std::atomic<PearCheckpointOutput>::is_always_lock_free);
#include "PearPhaseRuntime.inc"

// Bounded development checkpoints use Wine's existing output path. No guest
// memory, account data, register dump or new runtime ABI is recorded here.
static void PearInitCheckpoint(const char* Phase, uint32_t Status, uint32_t Domain, int32_t Code) {
  const auto Output = PearCheckpointSink.load(std::memory_order_acquire);
  if (!Output) return;
  char Text[192];
  snprintf(Text, sizeof(Text), "Pear FEX init %s: status=%08x domain=%u code=%d\n", Phase, Status, Domain, Code);
  Output(Text);
}

#ifdef PEAR_FEX_MEMORY_OWNER
// Startup-only opt-in. Gate records use the existing resolved sink, outside
// registry locks. No last-phase state is shared between recursive invocations.
static bool PearEntryObserve {};
#include "PearThreadCreateRuntime.inc"
#include "PearSlotLifetimeRuntime.inc"

#include "PearAbortObservation.h"
static bool PearAbortOptIn {};
// Slots are never reused in a process; a lost/overflowed record cannot bind later.
struct PearAbortSlot { std::atomic<unsigned> State {}; PearAbortRecord Record {}; };
static PearAbortSlot PearAbortSlots[8];
static std::atomic<unsigned> PearAbortNext {};
static_assert(std::atomic<unsigned>::is_always_lock_free);
extern "C" bool PearAbortEnabled() { return PearAbortOptIn && PearEntryObserve && PearPhaseOptIn; }
static bool PearAbortSame(const PearAbortRecord& a,const PearAbortRecord& b) {
  return a.pid==b.pid && a.tid==b.tid && a.guard==b.guard &&
    a.allocation==b.allocation && a.generation==b.generation && a.extent==b.extent &&
    a.size==b.size && a.epoch==b.epoch && a.expected==b.expected &&
    a.aclass==b.aclass && a.role==b.role && a.continuation==b.continuation;
}
extern "C" uint64_t PearAbortBegin(const PearAbortRecord* Record) {
  if (!PearAbortEnabled()) return 0;
  unsigned Slot=PearAbortNext.load(std::memory_order_relaxed);
  do { if (Slot>=8) return 0; } while (!PearAbortNext.compare_exchange_weak(Slot,Slot+1,std::memory_order_relaxed));
  auto d=*Record; d.pid=PearPhasePID; d.tid=GetCurrentThreadId(); d.call=Slot+1;
  PearAbortSlots[Slot].Record=d;
  PearAbortSlots[Slot].State.store(2,std::memory_order_release); return Slot+1;
}
#include "PearMismatchObservation.h"
static std::atomic<unsigned> PearMismatchEmitted {};
extern "C" void PearMismatchEmit(const PearMismatchRecord* Record) {
  if (!PearAbortEnabled() || Record->abort.call!=1) return;
  const auto Output=PearCheckpointSink.load(std::memory_order_acquire);
  if (!Output) return;
  auto m=*Record; m.abort.pid=PearPhasePID; m.abort.tid=GetCurrentThreadId();
  const auto& Slot=PearAbortSlots[0];
  if (Slot.State.load(std::memory_order_acquire)!=2 ||
      !PearAbortSame(m.abort,Slot.Record) || m.abort.life!=Slot.Record.life) return;
  unsigned Expected=0;
  if (!PearMismatchEmitted.compare_exchange_strong(Expected,1,std::memory_order_relaxed)) return;
  const int SavedErrno=errno; const DWORD SavedError=GetLastError();
  char Text[2048]; const int Length=pear_mismatch_format(Text,sizeof(Text),&m);
  if (Length>0 && static_cast<size_t>(Length)<sizeof(Text)) Output(Text);
  SetLastError(SavedError); errno=SavedErrno;
}
#include "PearTargetObservation.h"
static std::atomic<unsigned> PearTargetEmitted {};
extern "C" void PearTargetEmit(const PearTargetRecord* Record) {
  if (!PearAbortEnabled() || Record->abort.call!=1) return;
  const auto Output=PearCheckpointSink.load(std::memory_order_acquire);if(!Output)return;
  auto t=*Record;t.abort.pid=PearPhasePID;t.abort.tid=GetCurrentThreadId();
  const auto& Slot=PearAbortSlots[0];
  if(Slot.State.load(std::memory_order_acquire)!=2 || !PearAbortSame(t.abort,Slot.Record) || t.abort.life!=Slot.Record.life)return;
  unsigned Expected=0;if(!PearTargetEmitted.compare_exchange_strong(Expected,1,std::memory_order_relaxed))return;
  const int SavedErrno=errno;const DWORD SavedError=GetLastError();
  char Text[2048];const int Length=pear_target_format(Text,sizeof(Text),&t);
  if(Length>0 && static_cast<size_t>(Length)<sizeof(Text))Output(Text);
  SetLastError(SavedError);errno=SavedErrno;
}
#include "PearWriterObservation.h"
static std::atomic<unsigned> PearWriterEmitted{};
extern "C" void PearWriterEmit(const PearTargetRecord* record,const PearWriterBatch* b) {
  if(!PearAbortEnabled() || !record || !b || record->abort.call!=1 || b->count>64)return;
  const auto output=PearCheckpointSink.load(std::memory_order_acquire);if(!output)return;
  auto t=*record;t.abort.pid=PearPhasePID;t.abort.tid=GetCurrentThreadId();
  const auto& slot=PearAbortSlots[0];
  if(slot.State.load(std::memory_order_acquire)!=2 || !PearAbortSame(t.abort,slot.Record) || t.abort.life!=slot.Record.life)return;
  unsigned expected=0;if(!PearWriterEmitted.compare_exchange_strong(expected,1,std::memory_order_relaxed))return;
  const int saved=errno;const DWORD last=GetLastError();char text[4096];int n;
  n=snprintf(text,sizeof(text),"PEAR_WRITER_CUT1 pid=%llu tid=%llu guard=%llu call=%llu life=%llu allocation=%llu generation=%llu extent=%llu size=%llu epoch=%llu expected=%llu aclass=%llu role=%llu continuation=%llu read_seen=%llu read_cut=%llu read_loss=%llu end_seen=%llu first=%llu last=%llu loss=%llu count=%llu\n",(unsigned long long)t.abort.pid,(unsigned long long)t.abort.tid,(unsigned long long)t.abort.guard,(unsigned long long)t.abort.call,(unsigned long long)t.abort.life,(unsigned long long)t.abort.allocation,(unsigned long long)t.abort.generation,(unsigned long long)t.abort.extent,(unsigned long long)t.abort.size,(unsigned long long)t.abort.epoch,(unsigned long long)t.abort.expected,(unsigned long long)t.abort.aclass,(unsigned long long)t.abort.role,(unsigned long long)t.abort.continuation,(unsigned long long)t.read.writer_seen,(unsigned long long)t.read.writer_cut,(unsigned long long)t.read.writer_loss,(unsigned long long)b->seen,(unsigned long long)b->first,(unsigned long long)b->last,(unsigned long long)b->lost,(unsigned long long)b->count);if(n>0 && size_t(n)<sizeof(text))output(text);
  for(size_t i=0;i<b->count;++i){const auto& w=b->rows[i];
    n=snprintf(text,sizeof(text),"PEAR_WRITER1 pid=%llu tid=%llu guard=%llu call=%llu life=%llu allocation=%llu generation=%llu extent=%llu size=%llu epoch=%llu expected=%llu aclass=%llu role=%llu continuation=%llu writer_sequence=%llu writer_pid=%llu writer_executor=%llu writer_thread=%llu writer_life=%llu writer_operation=%llu writer_source=%llu writer_owner=%llu writer_state=%llu writer_allocation=%llu writer_generation=%llu writer_extent=%llu writer_size=%llu writer_base=%llu writer_aclass=%llu writer_role=%llu writer_offset=%llu writer_bytes=%llu writer_store_mask=%llu writer_changed_mask=%llu writer_before_epoch=%llu writer_write_epoch=%llu writer_turn=%llu writer_original0=%llu writer_original1=%llu writer_original2=%llu writer_next0=%llu writer_next1=%llu writer_next2=%llu writer_stores_done=%llu writer_terminal=%llu writer_publish_success=%llu writer_source_updated=%llu writer_status=%llu writer_domain=%llu writer_code=%llu\n",(unsigned long long)t.abort.pid,(unsigned long long)t.abort.tid,(unsigned long long)t.abort.guard,(unsigned long long)t.abort.call,(unsigned long long)t.abort.life,(unsigned long long)t.abort.allocation,(unsigned long long)t.abort.generation,(unsigned long long)t.abort.extent,(unsigned long long)t.abort.size,(unsigned long long)t.abort.epoch,(unsigned long long)t.abort.expected,(unsigned long long)t.abort.aclass,(unsigned long long)t.abort.role,(unsigned long long)t.abort.continuation,(unsigned long long)w.sequence,(unsigned long long)w.pid,(unsigned long long)w.executor,(unsigned long long)w.thread,(unsigned long long)w.life,(unsigned long long)w.operation,(unsigned long long)w.source,(unsigned long long)w.owner,(unsigned long long)w.state,(unsigned long long)w.allocation,(unsigned long long)w.generation,(unsigned long long)w.extent,(unsigned long long)w.size,(unsigned long long)w.base,(unsigned long long)w.aclass,(unsigned long long)w.role,(unsigned long long)w.offset,(unsigned long long)w.bytes,(unsigned long long)w.store_mask,(unsigned long long)w.changed_mask,(unsigned long long)w.before_epoch,(unsigned long long)w.write_epoch,(unsigned long long)w.turn,(unsigned long long)w.original0,(unsigned long long)w.original1,(unsigned long long)w.original2,(unsigned long long)w.next0,(unsigned long long)w.next1,(unsigned long long)w.next2,(unsigned long long)w.stores_done,(unsigned long long)w.terminal,(unsigned long long)w.publish_success,(unsigned long long)w.source_updated,(unsigned long long)w.status,(unsigned long long)w.domain,(unsigned long long)w.code);if(n>0 && size_t(n)<sizeof(text))output(text);
  }
  SetLastError(last);errno=saved;
}
extern "C" void PearAbortEmit(unsigned Side, const PearAbortRecord* Record) {
  if (!PearAbortEnabled() || Side<1 || Side>2) return;
  const auto Output=PearCheckpointSink.load(std::memory_order_acquire);
  if (!Output) return;
  auto d=*Record; d.pid=PearPhasePID; d.tid=GetCurrentThreadId();
  if (Side==2) {
    unsigned Index=8, Matches=0;
    for (unsigned i=0;i<8;++i) if (PearAbortSlots[i].State.load(std::memory_order_acquire)==2 && PearAbortSame(d,PearAbortSlots[i].Record)) { Index=i; ++Matches; }
    if (Matches!=1) return;
    unsigned Expected=2;
    if (!PearAbortSlots[Index].State.compare_exchange_strong(Expected,3,std::memory_order_acq_rel)) return;
    d.call=PearAbortSlots[Index].Record.call; d.life=PearAbortSlots[Index].Record.life;
  } else {
    if (!d.call || d.call>8) return;
    auto& Slot=PearAbortSlots[d.call-1];
    if (!PearAbortSame(d,Slot.Record) || d.life!=Slot.Record.life) return;
    if (Slot.State.exchange(4,std::memory_order_acq_rel)==4) return;
    if (!d.status) return;
  }
  const int SavedErrno=errno; const DWORD SavedError=GetLastError();
  char Text[1536]; const int Length=pear_abort_format(Text,sizeof(Text),Side,&d);
  if (Length>0 && static_cast<size_t>(Length)<sizeof(Text)) Output(Text);
  SetLastError(SavedError); errno=SavedErrno;
}

static uint32_t PearEntryPID {};
static std::atomic<unsigned> PearEntryRecords {};
static void PearEntryObservation(unsigned Mode, const PearMemory::EntryDiagnostic& D, PearMemory::Result R) {
  if (!PearEntryObserve || R) return;
  const auto Output = PearCheckpointSink.load(std::memory_order_acquire);
  if (!Output) return;
  unsigned Slot = PearEntryRecords.load(std::memory_order_relaxed);
  do { if (Slot >= 16) return; }
  while (!PearEntryRecords.compare_exchange_weak(Slot, Slot+1, std::memory_order_relaxed));
  const int SavedErrno = errno;
  const DWORD SavedError = GetLastError();
  char Text[512];
  snprintf(Text, sizeof(Text), "PEAR_ECENTRY1 pid=%lu tid=%lu mode=%u phase=%u status=%u domain=%u code=%d facts=%u known=%u\n",
           static_cast<unsigned long>(PearEntryPID), static_cast<unsigned long>(GetCurrentThreadId()),
           Mode, D.Phase, R.Status, R.ErrorDomain, R.ErrorCode, D.Facts, D.Known);
  Output(Text);
  SetLastError(SavedError);
  errno = SavedErrno;
}

// Failure-only local wait counters; no clock, VM query or scheduling policy.
static std::atomic<unsigned> PearMutationRecords {};
extern "C" void PearMutationBoundObservation(uint64_t Executor, uint64_t FirstOwner, uint64_t LastOwner,
    uint32_t Attempts, uint32_t OwnerChanges, uint32_t SequenceChanges, uint32_t WaitsOK, uint32_t WaitTimeouts, uint32_t Polls) {
  if (!PearEntryObserve) return;
  const auto Output=PearCheckpointSink.load(std::memory_order_acquire);
  if (!Output) return;
  unsigned Slot=PearMutationRecords.load(std::memory_order_relaxed);
  do { if (Slot>=16) return; }
  while (!PearMutationRecords.compare_exchange_weak(Slot,Slot+1,std::memory_order_relaxed));
  const int SavedErrno=errno;
  const DWORD SavedError=GetLastError();
  char Text[512];
  snprintf(Text,sizeof(Text),"PEAR_MUTATION1 pid=%lu tid=%lu seq=%u executor=%llu first=%llu last=%llu attempts=%u owner_changes=%u sequence_changes=%u waits_ok=%u wait_timeouts=%u polls=%u\n",
      static_cast<unsigned long>(PearEntryPID),static_cast<unsigned long>(GetCurrentThreadId()),Slot,
      static_cast<unsigned long long>(Executor),static_cast<unsigned long long>(FirstOwner),static_cast<unsigned long long>(LastOwner),
      Attempts,OwnerChanges,SequenceChanges,WaitsOK,WaitTimeouts,Polls);
  Output(Text);SetLastError(SavedError);errno=SavedErrno;
}

// Source-turn failure metadata, independent of the native owner's timeout path.
static std::atomic<unsigned> PearMutationOwnerRecords {};
extern "C" bool PearMutationOwnerObservationEnabled() {
  return PearEntryObserve && PearCheckpointSink.load(std::memory_order_acquire);
}
extern "C" void PearMutationOwnerObservation(uint64_t Executor, uint64_t Owner, uint32_t State,
    uint64_t WineThread, uint64_t Serial, uint32_t Role, uint32_t Lease, uint32_t Holds, uint32_t Flags, uint32_t Transition) {
  if (!PearEntryObserve) return;
  const auto Output=PearCheckpointSink.load(std::memory_order_acquire);
  if (!Output) return;
  unsigned Slot=PearMutationOwnerRecords.load(std::memory_order_relaxed);
  do { if (Slot>=16) return; }
  while (!PearMutationOwnerRecords.compare_exchange_weak(Slot,Slot+1,std::memory_order_relaxed));
  const int SavedErrno=errno;
  const DWORD SavedError=GetLastError();
  char Text[512];
  snprintf(Text,sizeof(Text),"PEAR_SOURCE_OWNER2 pid=%lu tid=%lu seq=%u executor=%llu owner=%llu state=%u wine_tid=%llu serial=%llu role=%u lease=%u holds=%u flags=%u transition=%u\n",
      static_cast<unsigned long>(PearEntryPID),static_cast<unsigned long>(GetCurrentThreadId()),Slot,
      static_cast<unsigned long long>(Executor),static_cast<unsigned long long>(Owner),State,
      static_cast<unsigned long long>(WineThread),static_cast<unsigned long long>(Serial),Role,Lease,Holds,Flags,Transition);
  Output(Text);SetLastError(SavedError);errno=SavedErrno;
}

// Early source-wait trigger for the existing external owned sampler.
static std::atomic<unsigned> PearMutationWaitRecords {};
extern "C" void PearMutationWaitObservation(uint64_t Executor, uint64_t Owner, uint32_t MutationSequence,
    uint32_t State, uint64_t WineThread, uint64_t Serial, uint32_t Role, uint32_t Lease,
    uint32_t Holds, uint32_t Flags, uint32_t Transition) {
  if (!PearEntryObserve) return;
  const auto Output=PearCheckpointSink.load(std::memory_order_acquire);
  if (!Output) return;
  unsigned Slot=PearMutationWaitRecords.load(std::memory_order_relaxed);
  do { if (Slot>=16) return; }
  while (!PearMutationWaitRecords.compare_exchange_weak(Slot,Slot+1,std::memory_order_relaxed));
  const int SavedErrno=errno;
  const DWORD SavedError=GetLastError();
  char Text[512];
  snprintf(Text,sizeof(Text),"PEAR_SOURCE_WAIT1 pid=%lu tid=%lu seq=%u executor=%llu owner=%llu state=%u wine_tid=%llu serial=%llu role=%u lease=%u holds=%u flags=%u transition=%u mutation_seq=%u attempts=200\n",
      static_cast<unsigned long>(PearEntryPID),static_cast<unsigned long>(GetCurrentThreadId()),Slot,
      static_cast<unsigned long long>(Executor),static_cast<unsigned long long>(Owner),State,
      static_cast<unsigned long long>(WineThread),static_cast<unsigned long long>(Serial),Role,Lease,Holds,Flags,Transition,MutationSequence);
  Output(Text);SetLastError(SavedError);errno=SavedErrno;
}

// Startup-only bounded completed-link observations. No owner/VM query is added.
static bool PearLinkObserve {};
static std::atomic<uint64_t> PearLinkOrdinals[2] {};
extern "C" bool PearLinkObservationEnabled() { return PearLinkObserve; }
extern "C" void PearLinkObservation(uint32_t Kind, uint32_t Reason, uint64_t A, uint64_t B) {
  if (!PearLinkObserve || Kind < 1 || Kind > 2) return;
  const auto Output = PearCheckpointSink.load(std::memory_order_acquire);
  if (!Output) return;
  auto& Counter = PearLinkOrdinals[Kind-1];
  auto Ordinal = Counter.load(std::memory_order_relaxed);
  do { if (Ordinal >= (uint64_t{1} << 63)) return; }
  while (!Counter.compare_exchange_weak(Ordinal, Ordinal+1, std::memory_order_relaxed));
  ++Ordinal;
  // Eight initial records and powers of two: at most 68 records per kind.
  if (Ordinal > 8 && (Ordinal & (Ordinal-1))) return;
  const int SavedErrno = errno;
  const DWORD SavedError = GetLastError();
  char Text[256];
  snprintf(Text, sizeof(Text), "PEAR_LINK1 pid=%lu tid=%lu kind=%u reason=%u ordinal=%llu a=%llu b=%llu\n",
           static_cast<unsigned long>(PearEntryPID), static_cast<unsigned long>(GetCurrentThreadId()),
           Kind, Reason, static_cast<unsigned long long>(Ordinal), static_cast<unsigned long long>(A), static_cast<unsigned long long>(B));
  Output(Text);
  SetLastError(SavedError);
  errno = SavedErrno;
}

// Failure-path callsite observation; no native owner or policy changes.
extern "C" bool PearFailureObservationEnabled() { return PearEntryObserve; }
static std::atomic<unsigned> PearFailureRecords {};
extern "C" void PearFailureObservation(uint32_t Kind, uintptr_t Caller, uint32_t Prior,
                                       uint32_t Status, uint32_t Domain, int32_t Code,
                                       uint32_t FirstStatus, uint32_t HasAllocation) {
  if (!PearEntryObserve) return;
  const auto Output = PearCheckpointSink.load(std::memory_order_acquire);
  if (!Output) return;
  unsigned Slot = PearFailureRecords.load(std::memory_order_relaxed);
  do { if (Slot >= 16) return; }
  while (!PearFailureRecords.compare_exchange_weak(Slot, Slot+1, std::memory_order_relaxed));
  const int SavedErrno = errno;
  const DWORD SavedError = GetLastError();
  char Text[256];
  snprintf(Text, sizeof(Text), "PEAR_FAILURE1 pid=%lu tid=%lu seq=%u kind=%u caller=%llx prior=%u status=%u domain=%u code=%d first=%u allocation=%u\n",
           static_cast<unsigned long>(PearEntryPID), static_cast<unsigned long>(GetCurrentThreadId()),
           Slot, Kind, static_cast<unsigned long long>(Caller), Prior, Status, Domain, Code, FirstStatus, HasAllocation);
  Output(Text);
  SetLastError(SavedError);
  errno = SavedErrno;
}

// Bounded repair revalidation facts; this observer grants no write authority.
static std::atomic<unsigned> PearRepairRecords {};
extern "C" void PearRepairObservation(uint32_t Reason, uint64_t A0, uint64_t A1, uint64_t D0, uint64_t D1) {
  if (!PearEntryObserve) return;
  const auto Output = PearCheckpointSink.load(std::memory_order_acquire);
  if (!Output) return;
  unsigned Slot = PearRepairRecords.load(std::memory_order_relaxed);
  do { if (Slot >= 16) return; }
  while (!PearRepairRecords.compare_exchange_weak(Slot, Slot+1, std::memory_order_relaxed));
  const int SavedErrno = errno;
  const DWORD SavedError = GetLastError();
  char Text[256];
  snprintf(Text, sizeof(Text), "PEAR_REPAIR1 pid=%lu tid=%lu seq=%u reason=%u a0=%llu a1=%llu d0=%llu d1=%llu\n",
           static_cast<unsigned long>(PearEntryPID), static_cast<unsigned long>(GetCurrentThreadId()),Slot,Reason,
           static_cast<unsigned long long>(A0),static_cast<unsigned long long>(A1),
           static_cast<unsigned long long>(D0),static_cast<unsigned long long>(D1));
  Output(Text); SetLastError(SavedError); errno = SavedErrno;
}

// The assembly wrapper preserves every guest GPR/SIMD register and FP/flag
// state across this compiled native gate. No generated code runs in the gate.
extern "C" void PearECGate(unsigned Mode) {
  const auto CPUArea = GetCPUArea();
  // Defer cooperative suspension until source lifetime and transition ownership
  // are released. The existing dispatcher/exit path services the doorbell.
  std::optional<ScopedCallbackDisable> CallbackDisable;
  if (CPUArea.Area) CallbackDisable.emplace();
  auto Life = PearMemory::AcquireCurrentSourceLifetime(CTX.get());
  auto* Thread = Life ? Life.ActualThread() : nullptr;
  PearMemory::Result Outcome {PEAR_FEX_UNAVAILABLE, 0, 0};
  PearMemory::EntryDiagnostic Diagnostic {};
  auto* Observation = PearEntryObserve ? &Diagnostic : nullptr;
  if (Mode <= 2 && PearSourceReady.load(std::memory_order_acquire) && CTX && CPUArea.Area &&
      Thread && CPUArea.ThreadState() == Thread && CPUArea.StateFrame() == Thread->CurrentFrame) {
    if (Mode == 2) Outcome = PearMemory::EntryFailure(Observation, 30, CTX->ExitPearEC(Thread, CPUArea.Area->InSimulation != 0));
    else Outcome = CTX->EnterPearEC(Thread, Mode == 1, Observation);
  }
  if (!Outcome) {
    PearMemory::EntryFailure(Observation, 1, Outcome);
    PearEntryObservation(Mode, Diagnostic, Outcome);
  }
  static std::atomic<unsigned> Observations {};
  if (!Outcome || Observations.fetch_add(1, std::memory_order_relaxed) < 16)
    PearInitCheckpoint(Mode == 2 ? "ECGate.exit" : Mode == 1 ? "ECGate.fill" : "ECGate.enter", Outcome.Status, Outcome.ErrorDomain, Outcome.ErrorCode);
  if (!Outcome) {
    PearRecordPrimary(Outcome);
    PearSourceReady.store(false, std::memory_order_release);
    PearSourceStatus.store(PearFailureStatus(Outcome), std::memory_order_release);
    // Preserve the existing downstream failure policy; never branch to a JIT
    // target after failed admission or return with an unresolved active lease.
    PEAR_FEX_REQUIRE_RESULT(!!Outcome, "Pear EC transition refused: status {}, domain {}, code {}", Outcome);
  }
  CPUArea.Area->InSimulation = Mode != 2;
#ifdef PEAR_PHASE_OBSERVE
  const auto PhaseReleased=Life.Release();
  PEAR_FEX_REQUIRE_RESULT(!!PhaseReleased,"Phase boundary lifetime release failed: status {}, domain {}, code {}",PhaseReleased);
  PearPhaseDrain();
#endif
}
#endif

NTSTATUS ProcessInit() {
#ifdef PEAR_FEX_MEMORY_OWNER
  if (CTX || PearSourceReady.load(std::memory_order_acquire)) {
    PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
    return STATUS_NOT_SUPPORTED;
  }
#endif

  InitSyscalls();

  FEX::Windows::InitCRTProcess();
  FEX::Windows::SetupThreadHandlers();
  const auto ExecutablePath = FEX::Windows::GetExecutableFilePath();
  AppConfigName = FEX::Windows::BaseName(ExecutablePath);
  FEX::Config::LoadConfig(AppConfigName, _environ, FEX::ReadPortabilityInformation());
  FEXCore::Config::ReloadMetaLayer();
#ifdef PEAR_FEX_DARWIN
  if (!FEX::Windows::DarwinPolicy::Apply()) {
#ifdef PEAR_FEX_MEMORY_OWNER
    PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
#endif
    return STATUS_NOT_SUPPORTED;
  }
#endif
  FEX::Windows::Logging::Init();
#ifdef PEAR_FEX_MEMORY_OWNER
  // Retain upstream fatal behavior but make its first bounded source reason
  // observable even when the default general logging policy is silent.
  LogMan::Msg::InstallHandler([](LogMan::DebugLevels Level,const char* Message) {
    if (Level!=LogMan::ERROR && Level!=LogMan::ASSERT) return;
    const auto Output=reinterpret_cast<int (*)(const char*)>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"__wine_dbg_output"));
    if (Output) { char Text[768]; snprintf(Text,sizeof(Text),"Pear FEX error: %.640s\n",Message); Output(Text); }
  });
  LogMan::Throw::InstallHandler([](const char* Message) {
    const auto Output=reinterpret_cast<int (*)(const char*)>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"__wine_dbg_output"));
    if (Output) { char Text[768]; snprintf(Text,sizeof(Text),"Pear FEX assertion: %.640s\n",Message); Output(Text); }
  });
#endif
  FEXCore::Config::Set(FEXCore::Config::CONFIG_APP_FILENAME, ExecutablePath);
  FEXCore::Config::Set(FEXCore::Config::CONFIG_APP_CONFIG_NAME, AppConfigName);

  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "1");

  FEXCore::Profiler::Init("", "");

  SignalDelegator = fextl::make_unique<FEX::DummyHandlers::DummySignalDelegator>();
  SyscallHandler = fextl::make_unique<Exception::ECSyscallHandler>();

  const auto NtDll = GetModuleHandleW(L"ntdll.dll");
  PearCheckpointSink.store(reinterpret_cast<PearCheckpointOutput>(GetProcAddress(NtDll, "__wine_dbg_output")),
                           std::memory_order_release);
#ifdef PEAR_PHASE_OBSERVE
  const char* PhaseOption=std::getenv("PEAR_PHASE_OBSERVE");
  PearPhaseOptIn=PhaseOption && PhaseOption[0]=='1' && PhaseOption[1]=='\0';
  PearPhaseRecords.Enable(PearPhaseOptIn);
#endif
  const bool IsWine = !!GetProcAddress(NtDll, "wine_get_version");
  OvercommitTracker.emplace(IsWine);

  FEX::Windows::SetupEnvironmentVariableValues(NtDll);
#ifdef PEAR_FEX_MEMORY_OWNER
  const char* EntryOptIn = std::getenv("PEAR_FEX_ENTRY_OBSERVE");
  PearEntryObserve = EntryOptIn && EntryOptIn[0] == '1' && EntryOptIn[1] == '\0';
  const auto AbortOptIn=getenv("PEAR_FEX_ABORT_OBSERVE");
  PearAbortOptIn=AbortOptIn && AbortOptIn[0]=='1' && AbortOptIn[1]=='\0';
  const char* LinkOptIn = std::getenv("PEAR_FEX_LINK_OBSERVE");
  PearLinkObserve = LinkOptIn && LinkOptIn[0] == '1' && LinkOptIn[1] == '\0';
#endif

  FEX::Windows::Allocator::SetupHooks(NtDll);
  FEX::Windows::UnixLib::Init(NtDll);
#ifdef PEAR_FEX_MEMORY_OWNER
  const auto EntryOwnerPID = FEX::Windows::UnixLib::GetPID();
  const auto OwnerInit = PearMemory::Init(NtDll, EntryOwnerPID);
  if (!OwnerInit) {
    PearRecordPrimary(OwnerInit); PearSourceStatus.store(PearFailureStatus(OwnerInit), std::memory_order_release);
    return PearFailureStatus(OwnerInit);
  }
  PearEntryPID = EntryOwnerPID;
#ifdef PEAR_PHASE_OBSERVE
  PearPhasePID = EntryOwnerPID;
#endif
#endif
  if (FEX::Windows::UnixLib::Available()) {
    FEXCore::DiskCache::SetFileMapper(FEX::Windows::UnixLib::MapFile);
  }

  {
    auto HostFeatures =
      FEX::Windows::CPUFeatures::FetchHostFeatures(IsWine, FEXCore::HostFeatures::HostTypeEnum::Arm64ec, FEX::Windows::UnixLib::GetPID());
#ifdef PEAR_FEX_MEMORY_OWNER
    PearMemory::Result Created;
    CTX=FEXCore::Context::Context::CreatePearContext(HostFeatures,Created);
    if (!Created) PearRecordPrimary(Created);
#else
    CTX = FEXCore::Context::Context::CreateNewContext(HostFeatures);
#endif
  }

#ifdef PEAR_FEX_MEMORY_OWNER
  if (!CTX) { PearCleanupPartialContext(STATUS_NO_MEMORY); return STATUS_NO_MEMORY; }
#endif
  CTX->SetSignalDelegator(SignalDelegator.get());
  CTX->SetSyscallHandler(SyscallHandler.get());
#ifdef PEAR_FEX_MEMORY_OWNER
  const auto Bootstrap = PearMemory::BindBootstrapContext(CTX.get());
  if (!Bootstrap) {
    const auto BootstrapStatus = PearFailureStatus(Bootstrap);
    PearCleanupPartialContext(BootstrapStatus, &Bootstrap);
    return BootstrapStatus;
  }
  const auto Registered = PearMemory::RegisterExecutor(PEAR_FEX_ROLE_ARM64EC);
  if (!Registered) {
    const auto RegisterStatus = PearFailureStatus(Registered);
    PearCleanupPartialContext(RegisterStatus, &Registered);
    return RegisterStatus;
  }
  // Actual Context bootstrap may publish only its source dispatcher. It cannot
  // reserve a shared JIT class, enter managed code or fabricate a ThreadState.
  PearMemory::Result CoreOutcome {};
  bool CoreReady {};
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
  try {
#endif
    CoreReady = CTX->InitPearCore(CoreOutcome);
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
  } catch (...) {
    PearSourceReady.store(false, std::memory_order_release);
    throw; // Preserve the actual upstream construction exception.
  }
#endif
  if (!CoreReady || !CoreOutcome) {
    const auto CoreStatus = PearFailureStatus(CoreOutcome);
    PearCleanupPartialContext(CoreStatus, &CoreOutcome);
    return CoreStatus;
  }
#else
  CTX->InitCore();
#endif
  Exception::HandlerConfig.emplace(*CTX);
#ifdef PEAR_FEX_MEMORY_OWNER
  // Allocate guest-only return data before the initial interval snapshot.
  X64ReturnInstr = ::VirtualAlloc(nullptr, FEXCore::Utils::FEX_PAGE_SIZE,
      MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
  if (!X64ReturnInstr) { PearCleanupPartialContext(STATUS_NO_MEMORY); return STATUS_NO_MEMORY; }
  *reinterpret_cast<uint8_t*>(X64ReturnInstr) = 0xc3;
  InvalidationTracker.emplace(*CTX, Threads, reinterpret_cast<uint64_t>(X64ReturnInstr), FEXCore::Utils::FEX_PAGE_SIZE);
#else
  InvalidationTracker.emplace(*CTX, Threads);
#endif
  ImageTracker.emplace(*CTX, false);

  auto MainModule = reinterpret_cast<__TEB*>(NtCurrentTeb())->Peb->ImageBaseAddress;
  HandleImageMap(reinterpret_cast<uint64_t>(MainModule), true);

  HandleImageMap(NtDllBase);

  CPUFeatures.emplace(*CTX);

#ifndef PEAR_FEX_MEMORY_OWNER
  X64ReturnInstr = ::VirtualAlloc(nullptr, FEXCore::Utils::FEX_PAGE_SIZE, MEM_COMMIT | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
  InvalidationTracker->HandleMemoryProtectionNotification(reinterpret_cast<uint64_t>(X64ReturnInstr), FEXCore::Utils::FEX_PAGE_SIZE,
                                                          PAGE_EXECUTE_READ);
  *reinterpret_cast<uint8_t*>(X64ReturnInstr) = 0xc3;
#endif

  const uintptr_t KiUserExceptionDispatcherFFS = reinterpret_cast<uintptr_t>(GetProcAddress(NtDll, "KiUserExceptionDispatcher"));
  Exception::KiUserExceptionDispatcher = NtDllRedirectionLUT[KiUserExceptionDispatcherFFS - NtDllBase] + NtDllBase;

  FEX_CONFIG_OPT(ProfileStats, PROFILESTATS);
  FEX_CONFIG_OPT(StartupSleep, STARTUPSLEEP);
  FEX_CONFIG_OPT(StartupSleepProcName, STARTUPSLEEPPROCNAME);

  if (IsWine && ProfileStats()) {
    StatAllocHandler = fextl::make_unique<FEX::Windows::StatAlloc>(FEXCore::SHMStats::AppType::WIN_ARM64EC);
  }

  if (StartupSleep() && (StartupSleepProcName().empty() || AppConfigName == StartupSleepProcName())) {
    LogMan::Msg::IFmt("[{}][{}] Sleeping for {} seconds", GetCurrentProcessId(), AppConfigName, StartupSleep());
    std::this_thread::sleep_for(std::chrono::seconds(StartupSleep()));
  }

#ifdef PEAR_FEX_MEMORY_OWNER
  PearInitCheckpoint("ProcessInit.complete", STATUS_SUCCESS);
  PearSourceStatus.store(STATUS_SUCCESS, std::memory_order_release);
  PearSourceReady.store(true, std::memory_order_release);
#endif
  return STATUS_SUCCESS;
}

void ProcessTerm(HANDLE Handle, BOOL After, NTSTATUS Status) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Delivered/source notification behavior is unqualified in this profile.
  PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
  return;
#endif
}


// Returns true if exception dispatch should be halted and the execution context restored to NativeContext
bool ResetToConsistentStateImpl(const ThreadCPUArea CPUArea, EXCEPTION_RECORD* Exception, CONTEXT* GuestContext, ARM64_NT_CONTEXT* NativeContext) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Delivered/source notification behavior is unqualified in this profile.
  PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
  return false;
#endif

  auto Thread = CPUArea.ThreadState();
  FEXCORE_PROFILE_ACCUMULATION(Thread, AccumulatedSignalTime);
  LogMan::Msg::DFmt("Exception: Code: {:X} Address: {:X}", Exception->ExceptionCode, reinterpret_cast<uintptr_t>(Exception->ExceptionAddress));

  if (NativeContext->Pc == reinterpret_cast<uint64_t>(&ExitFunctionSuspendPoint)) {
    // A suspend interrupt can occur in ExitFunctionEC before InSimulation is unset and set SuspendDoorbell. If this
    // occurs then it is still our duty to cooperatively suspend with an appropriate context. To support this, after
    // unsetting InSimulation a brk #0xCAFE instruction will be raised that we can handle here.
    NativeContext->Pc = reinterpret_cast<uintptr_t>(&ExitFunctionSuspendResumePoint); // Jump to the suspend resume point.
    *CPUArea.Area->SuspendDoorbell = 0;
    return true;
  }

  if (Exception->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
    const auto FaultAddress = static_cast<uint64_t>(Exception->ExceptionInformation[1]);

    if (FEX::Windows::CallRetStack::HandleAccessViolation(Thread, FaultAddress, NativeContext->X17)) {
      return true;
    }

    if (FEX::Windows::JITGuardPage::HandleJITGuardPage(Thread, reinterpret_cast<void*>(FaultAddress), NativeContext->X,
                                                       reinterpret_cast<__uint128_t*>(NativeContext->V), &NativeContext->Pc)) {
      return true;
    }

    std::scoped_lock Lock(ThreadCreationMutex);
    if (InvalidationTracker && InvalidationTracker->HandleRWXAccessViolation(Thread, NativeContext->Pc, FaultAddress)) {
      FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedSMCCount, 1);
      if (CTX->IsAddressInCodeBuffer(Thread, NativeContext->Pc) && !CTX->IsCurrentBlockSingleInst(CPUArea.ThreadState()) &&
          CTX->IsAddressInCurrentBlock(Thread, FaultAddress & FEXCore::Utils::FEX_PAGE_MASK, FEXCore::Utils::FEX_PAGE_SIZE)) {
        // If we are not patching ourself (single inst block case) and potentially patching the current block, this is inline SMC. Reconstruct the current context (before the SMC write) then single step the write to reduce it to regular SMC.
        Exception::ReconstructThreadState(Thread, *NativeContext);
        LogMan::Msg::DFmt("Handled inline self-modifying code: pc: {:X} rip: {:X} fault: {:X}", NativeContext->Pc,
                          Thread->CurrentFrame->State.rip, FaultAddress);
        NativeContext->Pc = CPUArea.DispatcherLoopTopEnterECFillSRA();
        NativeContext->Sp = CPUArea.EmulatorStackBase();
        NativeContext->X11 = 1;                                        // Set ENTRY_FILL_SRA_SINGLE_INST_REG to force a single step
        NativeContext->X17 = reinterpret_cast<uint64_t>(CPUArea.Area); // Set EC_ENTRY_CPUAREA_REG
      } else {
        LogMan::Msg::DFmt("Handled self-modifying code: pc: {:X} fault: {:X}", NativeContext->Pc, FaultAddress);
      }

      return true;
    }
  }

  bool IsJIT = CTX->IsAddressInCodeBuffer(Thread, NativeContext->Pc);
  if (Exception->ExceptionCode == EXCEPTION_DATATYPE_MISALIGNMENT && Exception::HandleUnalignedAccess(CPUArea, *NativeContext, IsJIT)) {
    LogMan::Msg::DFmt("Handled unaligned atomic: new pc: {:X}", NativeContext->Pc);
    return true;
  }

  if (!IsJIT && !IsDispatcherAddress(NativeContext->Pc)) {
    LogMan::Msg::DFmt("Passing through exception");
    return false;
  }

  // The JIT (in CompileBlock) emits code to check the suspend doorbell at the start of every block, and run the following instruction if it is set:
  static constexpr uint32_t SuspendTrapMagic {0xD4395FC0}; // brk #0xCAFE
  if (Exception->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION && *reinterpret_cast<uint32_t*>(NativeContext->Pc) == SuspendTrapMagic) {
    Exception::ReconstructThreadState(Thread, *NativeContext);
    *NativeContext = Exception::StoreStateToPackedECContext(Thread, NativeContext->Fpcr, NativeContext->Fpsr);
    LogMan::Msg::DFmt("Suspending: RIP: {:X} SP: {:X}", NativeContext->Pc, NativeContext->Sp);
    CPUArea.Area->InSimulation = 0;
    *CPUArea.Area->SuspendDoorbell = 0;
    return true;
  }

  if (IsEmulatorStackAddress(CPUArea, reinterpret_cast<uint64_t>(__builtin_frame_address(0)))) {
    Exception::RethrowGuestException(*Exception, *NativeContext);
    LogMan::Msg::DFmt("Rethrowing onto guest stack: {:X}", NativeContext->Sp);
    return true;
  } else {
    LogMan::Msg::EFmt("Unexpected exception in JIT code on guest stack");
    return false;
  }
}

#ifdef PEAR_FEX_MEMORY_OWNER
// Reuse upstream state reconstruction, ARM64EC packing and exception mapping.
// All source holds and callback guards end before a nonlocal NT continuation.
static NTSTATUS PearResetOwnedException(EXCEPTION_RECORD* Record, ARM64_NT_CONTEXT* Native) {
  const auto CPUArea=GetCPUArea();
  auto* Thread=CPUArea.ThreadState();
  if (!Thread || !CTX) return STATUS_SUCCESS;
  enum class Action { NativeResume, GuestResume, GuestRaise };
  Action Next=Action::GuestRaise;
  ARM64_NT_CONTEXT Packed {};
  EXCEPTION_RECORD GuestRecord {};
  BOOL FirstChance=TRUE;
  {
    ScopedCallbackDisable Callback;
    auto Life=PearMemory::AcquireCurrentSourceLifetime(CTX.get());
    if (!Life || Life.ActualThread()!=Thread || !Life.Validate()) return STATUS_NOT_SUPPORTED;
    if (Native->Pc==reinterpret_cast<uintptr_t>(&ExitFunctionSuspendPoint)) {
      Life.ObserveWakeCheckpoint(1);
      const auto Idle=CTX->ExitPearEC(Thread,false);
      if (!Idle) { PearRecordPrimary(Idle); return STATUS_NOT_SUPPORTED; }
      Native->Pc=reinterpret_cast<uintptr_t>(&ExitFunctionSuspendResumePoint);
      *CPUArea.Area->SuspendDoorbell=0;
      Next=Action::NativeResume;
    } else {
      const bool IsJIT=CTX->IsAddressInCodeBuffer(Thread,Native->Pc);
      const bool IsDispatcher=IsDispatcherAddress(Native->Pc);
      if (!IsJIT && !IsDispatcher) return STATUS_SUCCESS;
      uint32_t Instruction {};
      const auto Observed=CTX->ObservePearInstruction(Thread,Native->Pc,Instruction);
      if (!Observed) { PearRecordPrimary(Observed); return STATUS_NOT_SUPPORTED; }
      bool UnalignedHandled=false;int32_t UnalignedResume=0;
      if (IsJIT && Record->ExceptionCode==EXCEPTION_DATATYPE_MISALIGNMENT) {
        const auto Repaired=CTX->RepairPearUnaligned(Thread,Native->Pc,UnalignedHandled,UnalignedResume);
        if (!Repaired) { PearRecordPrimary(Repaired); return STATUS_NOT_SUPPORTED; }
      }
      if (UnalignedHandled) {
        Native->Pc+=UnalignedResume;
        PearInitCheckpoint("Unaligned.repaired",STATUS_SUCCESS,0,UnalignedResume);
        Next=Action::NativeResume;
      } else if (Record->ExceptionCode==EXCEPTION_ACCESS_VIOLATION && Record->NumberParameters>=2 &&
          FEX::Windows::CallRetStack::HandleAccessViolation(Thread,Record->ExceptionInformation[1],Native->X17)) {
        Next=Action::NativeResume;
      } else {
        const bool Suspend=Record->ExceptionCode==EXCEPTION_ILLEGAL_INSTRUCTION && Instruction==0xD4395FC0;
        if (Suspend) Life.ObserveWakeCheckpoint(2);
        if (!IsDispatcher) Exception::ReconstructThreadState(Thread,*Native);
        Packed=Exception::StoreStateToPackedECContext(Thread,Native->Fpcr,Native->Fpsr);
        if (Suspend) {
          Next=Action::GuestResume;
          *CPUArea.Area->SuspendDoorbell=0;
        } else {
          auto Flags=CTX->ReconstructCompactedEFLAGS(Thread,false,nullptr,0);
          Flags &= ~(1U<<FEXCore::X86State::RFLAG_TF_RAW_LOC);
          CTX->SetFlagsFromCompactedEFLAGS(Thread,Flags);
          GuestRecord=FEX::Windows::HandleGuestException(Thread->CurrentFrame->SynchronousFaultData,*Record,
                                                        Packed.Pc,Packed.X8,Packed.X0,FirstChance);
          if (GuestRecord.ExceptionCode==EXCEPTION_SINGLE_STEP) Packed.Cpsr &= ~(1U<<21);
          else if (GuestRecord.ExceptionCode==EXCEPTION_BREAKPOINT) --Packed.Pc;
        }
        const auto Exited=CTX->ExitPearEC(Thread,true);
        if (!Exited) { PearRecordPrimary(Exited); return STATUS_NOT_SUPPORTED; }
        CPUArea.Area->InSimulation=false;
      }
    }
    const auto Released=Life.Release();
    if (!Released) { PearRecordPrimary(Released); return STATUS_NOT_SUPPORTED; }
  }
  if (Next==Action::NativeResume) return NtContinueNative(Native,false);
  CPUArea.Area->InSyscallCallback=false;
  if (Next==Action::GuestResume) return NtContinueNative(&Packed,false);
  PearInitCheckpoint("GuestException.delivered",GuestRecord.ExceptionCode);
#ifdef PEAR_PHASE_OBSERVE
  PearPhaseRecords.EndThread(GetCurrentThreadId(),GetFrontendThreadData(Thread)->PhaseLifetime);
  PearPhaseDrain();
#endif
  return NtRaiseExceptionNative(&GuestRecord,&Packed,FirstChance);
}
#endif

NTSTATUS ResetToConsistentState(EXCEPTION_RECORD* Exception, CONTEXT* GuestContext, ARM64_NT_CONTEXT* NativeContext) {
  bool Cont {};
  if (Exception->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && Exception->NumberParameters >= 2 &&
      Exception->ExceptionInformation[0] < 2) {
    const auto FaultAddress = static_cast<uint64_t>(Exception->ExceptionInformation[1]);

    if (OvercommitTracker) {
      NTSTATUS Failure {};
      {
        ScopedCallbackDisable guard;
        Cont = OvercommitTracker->HandleAccessViolation(FaultAddress, &Failure);
      }
      if (Failure) {
        PearInitCheckpoint("Overcommit.refused", Failure);
        return Failure;
      }
      if (Cont) {
        static std::atomic<unsigned> Observations {};
        if (Observations.fetch_add(1, std::memory_order_relaxed) < 8)
          PearInitCheckpoint("Overcommit.committed", STATUS_SUCCESS);
        // Private bounded diagnosis of Wine's native/guest resume selection.
        const auto* PEB = reinterpret_cast<const uint8_t*>(NtCurrentTeb()->ProcessEnvironmentBlock);
        const auto* Bitmap = *reinterpret_cast<const uint64_t* const*>(PEB + 0x368);
        const auto Page = NativeContext->Pc >> 12;
        PearInitCheckpoint("Overcommit.resume-class", Bitmap ? (Bitmap[Page / 64] >> (Page & 63)) & 1 : 2,
                           NativeContext->ContextFlags, static_cast<int32_t>(NativeContext->Pc));
        PearInitCheckpoint("Overcommit.syscall-id", static_cast<uint32_t>(WineNtContinueSyscallId));
        const auto Status = NtContinueNative(NativeContext, false);
        PearInitCheckpoint("Overcommit.continue-returned", Status);
        return Status ? Status : STATUS_UNSUCCESSFUL;
      }
    }
  }

#ifdef PEAR_FEX_MEMORY_OWNER
  return PearResetOwnedException(Exception,NativeContext);
#endif

  const auto CPUArea = GetCPUArea();
  if (!CPUArea.ThreadState()) {
    return STATUS_SUCCESS;
  }

  {
    ScopedCallbackDisable guard;
    Cont = ResetToConsistentStateImpl(CPUArea, Exception, GuestContext, NativeContext);
  }

  if (Cont) {
    NtContinueNative(NativeContext, false);
  }

  CPUArea.Area->InSimulation = false;
  CPUArea.Area->InSyscallCallback = false;
  return STATUS_SUCCESS;
}

#ifdef PEAR_FEX_MEMORY_OWNER
enum PearNotificationKind : unsigned { PearAlloc=1, PearFree, PearProtect, PearUnmap };
static void PearMemoryNotification(PearNotificationKind Kind, void* Address, SIZE_T Size,
                                   ULONG Argument, ULONG Prot, BOOL After, NTSTATUS Status) {
  if (!CTX || !InvalidationTracker) return;
  auto* Thread=GetCPUArea().ThreadState();
  if (!Thread) return;
  auto* Frontend=GetFrontendThreadData(Thread);
  auto Refused=[=](PearMemory::Result Result) {
    PearRecordPrimary(Result); PearSourceReady.store(false,std::memory_order_release);
    LogMan::Msg::EFmt("Pear memory notification kind {} after {} refused",static_cast<unsigned>(Kind),!!After);
    PearInitCheckpoint("MemoryNotification.refused",Result.Status,Result.ErrorDomain,Result.ErrorCode);
  };
  if (!After) {
    if (!PearSourceReady.load(std::memory_order_acquire)) return;
    if (Frontend->MemoryNotificationKind || Frontend->MemoryNotificationLife) {
      Refused({PEAR_FEX_STALE_IDENTITY,0,0}); return;
    }
    auto Life=PearMemory::AcquireCurrentSourceLifetime(CTX.get());
    if (!Life || Life.ActualThread()!=Thread) { Refused({PEAR_FEX_STALE_IDENTITY,0,0}); return; }
    auto Result=CTX->BeginPearLinkInvalidation(Thread);
    if (!Result) { Refused(Result); return; }
    // Reuse the upstream before/after serialization. Quiescence admission is
    // acquired before this mutex, and completion waits occur after unlocking.
    ThreadCreationMutex.lock();
    Frontend->MemoryNotificationLife.emplace(std::move(Life));
    Frontend->MemoryNotificationKind=Kind;
    if (Kind==PearUnmap || (Kind==PearFree && (Argument & MEM_RELEASE))) {
      auto [Start,Bytes]=InvalidationTracker->InvalidateContainingSection(reinterpret_cast<uint64_t>(Address),false);
      Frontend->MemoryNotificationStart=Start;
      Frontend->MemoryNotificationSize=Bytes;
    }
    return;
  }
  // A refused before-callback creates no lock/record. Preserve its failure.
  if (!Frontend->MemoryNotificationKind && !Frontend->MemoryNotificationLife) return;
  if (Frontend->MemoryNotificationKind!=Kind || !Frontend->MemoryNotificationLife ||
      !Frontend->MemoryNotificationLife->Validate()) { Refused({PEAR_FEX_STALE_IDENTITY,0,0}); return; }
  if (!Status) {
    if (Kind==PearProtect || (Kind==PearAlloc && !(Argument & (MEM_RESET|MEM_RESET_UNDO))))
      InvalidationTracker->HandleMemoryProtectionNotification(reinterpret_cast<uint64_t>(Address),Size,Prot);
    else if (Kind==PearFree && !(Argument & MEM_RELEASE))
      InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address),Size,true);
    else if ((Kind==PearUnmap || Kind==PearFree) && Frontend->MemoryNotificationSize) {
      // Before invalidated cached translations, but a failed VM operation must
      // retain the live guest permissions and image tracker. Remove only after
      // observed success while the original owner batch remains admitted.
      InvalidationTracker->InvalidateAlignedInterval(Frontend->MemoryNotificationStart,Frontend->MemoryNotificationSize,true);
      if (Kind==PearUnmap) HandleImageUnmap(Frontend->MemoryNotificationStart,Frontend->MemoryNotificationSize);
    }
  }
  Frontend->MemoryNotificationKind=0;
  Frontend->MemoryNotificationStart=Frontend->MemoryNotificationSize=0;
  ThreadCreationMutex.unlock();
  const auto Finished=CTX->FinishPearLinkInvalidation(Thread);
  const auto Released=Frontend->MemoryNotificationLife->Release();
  if (Released) Frontend->MemoryNotificationLife.reset();
  if (!Finished) Refused(Finished);
  else if (!Released) Refused(Released);
}
#endif

void NotifyMemoryAlloc(void* Address, SIZE_T Size, ULONG Type, ULONG Prot, BOOL After, NTSTATUS Status) {
#ifdef PEAR_FEX_MEMORY_OWNER
  PearMemoryNotification(PearAlloc,Address,Size,Type,Prot,After,Status);
  return;
#endif

  if (!InvalidationTracker || !GetCPUArea().ThreadState()) {
    return;
  }

  if (!After) {
    ThreadCreationMutex.lock();
  } else {
    // MEM_RESET(_UNDO) ignores the passed permissions
    if (!Status && !(Type & (MEM_RESET | MEM_RESET_UNDO))) {
      InvalidationTracker->HandleMemoryProtectionNotification(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), Prot);
    }
    ThreadCreationMutex.unlock();
  }
}

void NotifyMemoryFree(void* Address, SIZE_T Size, ULONG FreeType, BOOL After, NTSTATUS Status) {
#ifdef PEAR_FEX_MEMORY_OWNER
  PearMemoryNotification(PearFree,Address,Size,FreeType,0,After,Status);
  return;
#endif

  if (!InvalidationTracker || !GetCPUArea().ThreadState()) {
    return;
  }

  if (!After) {
    ThreadCreationMutex.lock();
  } else {
    if (!Status) {
      InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), true);
    }
    ThreadCreationMutex.unlock();
  }
}

void NotifyMemoryProtect(void* Address, SIZE_T Size, ULONG NewProt, BOOL After, NTSTATUS Status) {
#ifdef PEAR_FEX_MEMORY_OWNER
  PearMemoryNotification(PearProtect,Address,Size,0,NewProt,After,Status);
  return;
#endif

  if (!InvalidationTracker || !GetCPUArea().ThreadState()) {
    return;
  }

  if (!After) {
    ThreadCreationMutex.lock();
  } else {
    if (!Status) {
      InvalidationTracker->HandleMemoryProtectionNotification(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), NewProt);
    }
    ThreadCreationMutex.unlock();
  }
}

NTSTATUS NotifyMapViewOfSection(void* Unk1, void* Address, void* Unk2, SIZE_T Size, ULONG AllocType, ULONG Prot) {
#ifdef PEAR_FEX_MEMORY_OWNER
  if (!PearSourceReady.load(std::memory_order_acquire) || !CTX || !InvalidationTracker || !ImageTracker ||
      !Address || !Size || reinterpret_cast<uintptr_t>(Address) > UINTPTR_MAX - Size) return STATUS_NOT_SUPPORTED;
  auto* Thread = GetCPUArea().ThreadState();
  auto Life = PearMemory::AcquireCurrentSourceLifetime(CTX.get());
  if (!Life || !Thread || Life.ActualThread() != Thread) return STATUS_NOT_SUPPORTED;
  // Acquire real source/owner write admission before any source coordination
  // lock. A mapped range can reuse a prior guest address, so invalidate it too.
  const auto Admitted = CTX->BeginPearLinkInvalidation(Thread);
  if (!Admitted) {
    PearRecordPrimary(Admitted);
    PearInitCheckpoint("NotifyMapView.admission", Admitted.Status, Admitted.ErrorDomain, Admitted.ErrorCode);
    return PearFailureStatus(Admitted);
  }
  bool Matched {};
  {
    std::scoped_lock Lock(ThreadCreationMutex);
    const auto Found = Threads.find(GetCurrentThreadId());
    Matched = Found != Threads.end() && Found->second == Thread;
    if (Matched) {
      InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), Size, false);
      HandleImageMap(reinterpret_cast<uint64_t>(Address));
    }
  }
  // Publication/abort may wait; finish only after releasing source locks.
  const auto Finished = CTX->FinishPearLinkInvalidation(Thread);
  if (!Finished) {
    PearRecordPrimary(Finished);
    PearInitCheckpoint("NotifyMapView.finish", Finished.Status, Finished.ErrorDomain, Finished.ErrorCode);
    return PearFailureStatus(Finished);
  }
  const auto Result = Matched ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
  PearInitCheckpoint("NotifyMapView.complete", Result);
  return Result;
#else

  if (!InvalidationTracker || !GetCPUArea().ThreadState()) {
    return STATUS_SUCCESS;
  }

  {
    std::scoped_lock Lock(ThreadCreationMutex);
    HandleImageMap(reinterpret_cast<uint64_t>(Address));
  }


  return STATUS_SUCCESS;
#endif
}

void NotifyUnmapViewOfSection(void* Address, BOOL After, NTSTATUS Status) {
#ifdef PEAR_FEX_MEMORY_OWNER
  PearMemoryNotification(PearUnmap,Address,0,0,0,After,Status);
  return;
#endif

  if (!InvalidationTracker || !GetCPUArea().ThreadState()) {
    return;
  }

  if (!After) {
    ThreadCreationMutex.lock();
    auto [Start, Size] = InvalidationTracker->InvalidateContainingSection(reinterpret_cast<uint64_t>(Address), true);
    if (Size) {
      HandleImageUnmap(Start, Size);
    }
  } else {
    ThreadCreationMutex.unlock();
  }
}

#ifdef PEAR_FEX_MEMORY_OWNER
static void PearInvalidateGuestRange(const void* Address, SIZE_T Size) {
  if (!CTX || !InvalidationTracker || !PearSourceReady.load(std::memory_order_acquire)) return;
  auto* Thread=GetCPUArea().ThreadState();
  if (!Thread) return;
  auto Life=PearMemory::AcquireCurrentSourceLifetime(CTX.get());
  PearMemory::Result Outcome {PEAR_FEX_STALE_IDENTITY,0,0};
  if (Life && Life.ActualThread()==Thread && (!Address || reinterpret_cast<uintptr_t>(Address)<=UINTPTR_MAX-Size)) {
    Outcome=CTX->BeginPearLinkInvalidation(Thread);
    if (Outcome) {
      {
        ScopedCallbackDisable Guard;
        std::scoped_lock Lock(ThreadCreationMutex);
        InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address),Size,false);
      }
      Outcome=CTX->FinishPearLinkInvalidation(Thread);
    }
  }
  if (!Outcome) { PearRecordPrimary(Outcome); PearSourceReady.store(false,std::memory_order_release); }
  PearInitCheckpoint("GuestInvalidate.complete",Outcome.Status,Outcome.ErrorDomain,Outcome.ErrorCode);
}
#endif

void FlushInstructionCacheHeavy(const void* Address, SIZE_T Size) {
#ifdef PEAR_FEX_MEMORY_OWNER
  PearInvalidateGuestRange(Address,Size);
  return;
#endif

  if (!InvalidationTracker || !GetCPUArea().ThreadState()) {
    return;
  }

  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
}

void BTCpu64FlushInstructionCache(const void* Address, SIZE_T Size) {
#ifdef PEAR_FEX_MEMORY_OWNER
  PearInvalidateGuestRange(Address,Size);
  return;
#endif

  if (!InvalidationTracker || !GetCPUArea().ThreadState()) {
    return;
  }

  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
}

void BTCpu64NotifyMemoryDirty(void* Address, SIZE_T Size) {
#ifdef PEAR_FEX_MEMORY_OWNER
  PearInvalidateGuestRange(Address,Size);
  return;
#endif

  if (!InvalidationTracker || !GetCPUArea().ThreadState()) {
    return;
  }

  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
}

void BTCpu64NotifyReadFile(HANDLE Handle, void* Address, SIZE_T Size, BOOL After, NTSTATUS Status) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Reuse upstream post-read invalidation. Never retain a global writer across
  // blocking I/O; asynchronous completion remains explicitly outside this path.
  if (After && Status==STATUS_SUCCESS) PearInvalidateGuestRange(Address,Size);
  return;
#endif

  auto* ThreadState = GetCPUArea().ThreadState();
  if (!InvalidationTracker || !ThreadState) {
    return;
  }

  // On file read this can cause JIT code invalidations. FEX previously used to hold locks on `CodeInvalidationMutex` and `ThreadCreationMutex` during
  // this. This was a problem that file reads are blocking and may necessarily never return. A simple unit-test that holds a blocking read, then tries
  // to create threads or JIT code would immediately hang.
  //
  // - PhysX msiexec installer (From Dishonored AppID 205100) did exactly this and hung forever.
  //
  // The alternative approach is to let the read progress as normal and only notify invalidation when the read actually returns. This introduces an
  // unavoidable race which by my logic is fine.
  //
  // 1) If a thread is already jitting code from the address range then in a "real" x86 environment it may see old, new, or a combination of both.
  //   - NtReadFile isn't guaranteed to return new data atomically, in order, or anything of the sort.
  // 2) The calling thread only ever sees the before code, and the after code because `NtReadFile` never leaves "kernel" space before invalidation.
  //
  // The only "gotcha" is that FEX could have write-protected the memory region when a JIT executed the code, and once the `NtReadFile` tries
  // returning data, it faults. This requires coordination between Wine and FEX in order to handle this edge case.
  //
  // Additionally, async reads are still completely untracked with invalidation, which never worked before anyway.

  if (AppConfigName == "P5R.exe") {
    // Use the locking mechanism for (Persona 5 Royal AppID 1687950) which does exactly the problem described above.
    auto& InLockedRWXRead = GetFrontendThreadData(ThreadState)->InLockedRWXRead;
    if (!After) {
      ThreadCreationMutex.lock();
      CTX->GetCodeInvalidationMutex().lock();
      if (InvalidationTracker->BeginUntrackedWriteLocked(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size))) {
        InLockedRWXRead = true;
      } else {
        CTX->GetCodeInvalidationMutex().unlock();
        ThreadCreationMutex.unlock();
      }
    } else {
      if (InLockedRWXRead) {
        InLockedRWXRead = false;
        CTX->GetCodeInvalidationMutex().unlock();
        ThreadCreationMutex.unlock();
      }
    }

    return;
  }

  if (After && Status == STATUS_SUCCESS) {
    std::scoped_lock Lock(ThreadCreationMutex);
    InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
  }
}

NTSTATUS ThreadInit() {
#ifdef PEAR_FEX_MEMORY_OWNER
  PearInitCheckpoint("ThreadInit.enter", PearSourceReady.load(std::memory_order_acquire) ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED);

  if (!PearSourceReady.load(std::memory_order_acquire) || !CTX) {
    PearSourceReady.store(false, std::memory_order_release); PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release); return STATUS_NOT_SUPPORTED;
  }
  PearThreadPreparation Preparation;
  if (!Preparation) {
    PearInitCheckpoint("ThreadInit.preparation", Preparation.Status());
    PearSourceReady.store(false, std::memory_order_release); PearSourceStatus.store(Preparation.Status(), std::memory_order_release); return Preparation.Status();
  }

  FEX::Windows::InitCRTThread();
  const auto CPUArea = GetCPUArea();

  static constexpr size_t EmulatorStackSize = 0x40000;
  const uint64_t EmulatorStack =
    reinterpret_cast<uint64_t>(::VirtualAlloc(nullptr, EmulatorStackSize, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE));
  if (!EmulatorStack) { PearSourceReady.store(false, std::memory_order_release); PearSourceStatus.store(STATUS_NO_MEMORY, std::memory_order_release); return STATUS_NO_MEMORY; }
  if (!CPUArea.Area || CPUArea.ThreadState()) {
    PearInitCheckpoint("ThreadInit.cpu-area", STATUS_NOT_SUPPORTED);
    ::VirtualFree(reinterpret_cast<void*>(EmulatorStack), 0, MEM_RELEASE);
    PearSourceReady.store(false, std::memory_order_release); PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release); return STATUS_NOT_SUPPORTED;
  }

#ifdef PEAR_PHASE_OBSERVE
  const bool PearCreateReadyBefore=PearSourceReady.load(std::memory_order_acquire);
#endif
  PearMemory::Result ThreadOutcome {}, ThreadCleanup {};
  bool ThreadCleanupAttempted {};
  FEXCore::Core::InternalThreadState* Thread {};
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
  try {
#endif
    Thread = CTX->CreatePearThread(nullptr, ThreadOutcome, &ThreadCleanup, &ThreadCleanupAttempted);
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
  } catch (...) {
    PearSourceReady.store(false, std::memory_order_release);
    throw; // Keep the original exception and native result history unchanged.
  }
#endif
  // Core binds/registers this actual state before InitializeCompiler and
  // retains/quarantines any source object with unresolved owner registration.
  if (!Thread || !ThreadOutcome) {
    PearInitCheckpoint("ThreadInit.create", ThreadOutcome.Status, ThreadOutcome.ErrorDomain, ThreadOutcome.ErrorCode);
#ifdef PEAR_PHASE_OBSERVE
    PearThreadCreateReport(CTX.get(),&ThreadOutcome,ThreadCleanup,ThreadCleanupAttempted,PearCreateReadyBefore);
#endif
    PearRecordPrimary(ThreadOutcome);
    // An explicit cleanup failure may itself return UNAVAILABLE. Preserve the
    // actual Core attempted flag even after a clean binding was released.
    if (ThreadCleanupAttempted)
      PearRecordCleanup(ThreadCleanup);
    const auto ThreadStatus = PearFailureStatus(ThreadOutcome);
    PearSourceReady.store(false, std::memory_order_release);
    PearSourceStatus.store(ThreadStatus, std::memory_order_release);
    ::VirtualFree(reinterpret_cast<void*>(EmulatorStack), 0, MEM_RELEASE);
    return ThreadStatus;
  }

  // Default segment setup.
  auto Frame = Thread->CurrentFrame;
  auto NewSegments = new FEXCore::Core::CPUState::gdt_segment[32];

  // Setup initial code-segment GDT
  auto& GDT = NewSegments[FEXCore::Core::CPUState::DEFAULT_USER_CS];
  FEXCore::Core::CPUState::SetGDTBase(&GDT, 0);
  FEXCore::Core::CPUState::SetGDTLimit(&GDT, 0xF'FFFFU);
  GDT.L = 1; // L = Long Mode = 64-bit
  GDT.D = 0; // D = Default Operand SIze = Reserved

  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = &NewSegments[0];
  // TODO: LDTs are currently unsupported, mirror them to GDT.
  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = &NewSegments[0];

  Frame->State.cs_idx = FEXCore::Core::CPUState::DEFAULT_USER_CS << 3;
  Frame->State.cs_cached = FEXCore::Core::CPUState::CalculateGDTBase(GDT);

  FEX::Windows::CallRetStack::InitializeThread(Thread);
  Thread->CurrentFrame->Pointers.ExitFunctionEC = reinterpret_cast<uintptr_t>(&ExitFunctionEC);

  uint64_t EnterEC = Thread->CurrentFrame->Pointers.DispatcherLoopTopEnterEC;

  uint64_t EnterECFillSRA = Thread->CurrentFrame->Pointers.DispatcherLoopTopEnterECFillSRA;

  ARM64EC_NT_CONTEXT InitialContext = {.ContextFlags = CONTEXT_CONTROL | CONTEXT_SEGMENTS | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT,
                            .AMD64_SegCs = (FEXCore::Core::CPUState::DEFAULT_USER_CS << 3) | 3,
                            .AMD64_SegDs = 0x2b,
                            .AMD64_SegEs = 0x2b,
                            .AMD64_SegFs = 0x53,
                            .AMD64_SegGs = 0x2b,
                            .AMD64_SegSs = 0x2b,
                            .AMD64_EFlags = 0x202,
                            .AMD64_MxCsr = 0x1f80,
                            .AMD64_MxCsr_copy = 0x1f80,
                            .AMD64_ControlWord = 0x27f};
  Exception::LoadStateFromECContext(Thread, InitialContext.AMD64_Context);

  Thread->FrontendPtr = new FrontendThreadData();

  bool Published {};
  {
    std::scoped_lock Lock(ThreadCreationMutex);
    const auto TID = Preparation.ID();
    if (!Threads.contains(TID) && !CPUArea.ThreadState()) {
      Threads.emplace(TID, Thread);
      if (StatAllocHandler) Thread->ThreadStats = StatAllocHandler->AllocateSlot(TID);
      CPUArea.EmulatorStackLimit() = EmulatorStack;
      CPUArea.EmulatorStackBase() = EmulatorStack + EmulatorStackSize;
      CPUArea.ContextAmd64() = InitialContext;
      CPUArea.StateFrame() = Thread->CurrentFrame;
      CPUArea.DispatcherLoopTopEnterEC() = EnterEC;
      CPUArea.DispatcherLoopTopEnterECFillSRA() = EnterECFillSRA;
      CPUArea.Area->SuspendDoorbell = reinterpret_cast<ULONG*>(&Thread->CurrentFrame->SuspendDoorbell);
      CPUArea.ThreadState() = Thread;
      Published = true;
    }
  }
  if (!Published) {
    // No forced cleanup of a constructed source state with unclosed lifetime.
    // Keep its owner identity/objects retained; this is a refused source gap.
    PearSourceReady.store(false, std::memory_order_release); PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
    return STATUS_NOT_SUPPORTED;
  }
  Preparation.Commit();
  LogMan::Msg::EFmt("Pear CPU thread tid={} state={:x}", GetCurrentThreadId(), reinterpret_cast<uintptr_t>(Thread));
  PearInitCheckpoint("ThreadInit.complete", STATUS_SUCCESS);
  return STATUS_SUCCESS;
#else

  std::scoped_lock Lock(ThreadCreationMutex);
  FEX::Windows::InitCRTThread();
  const auto CPUArea = GetCPUArea();

  static constexpr size_t EmulatorStackSize = 0x40000;
  const uint64_t EmulatorStack =
    reinterpret_cast<uint64_t>(::VirtualAlloc(nullptr, EmulatorStackSize, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE));
  CPUArea.EmulatorStackLimit() = EmulatorStack;
  CPUArea.EmulatorStackBase() = EmulatorStack + EmulatorStackSize;

  auto* Thread = CTX->CreateThread();

  // Default segment setup.
  auto Frame = Thread->CurrentFrame;
  auto NewSegments = new FEXCore::Core::CPUState::gdt_segment[32];

  // Setup initial code-segment GDT
  auto& GDT = NewSegments[FEXCore::Core::CPUState::DEFAULT_USER_CS];
  FEXCore::Core::CPUState::SetGDTBase(&GDT, 0);
  FEXCore::Core::CPUState::SetGDTLimit(&GDT, 0xF'FFFFU);
  GDT.L = 1; // L = Long Mode = 64-bit
  GDT.D = 0; // D = Default Operand SIze = Reserved

  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = &NewSegments[0];
  // TODO: LDTs are currently unsupported, mirror them to GDT.
  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = &NewSegments[0];

  Frame->State.cs_idx = FEXCore::Core::CPUState::DEFAULT_USER_CS << 3;
  Frame->State.cs_cached = FEXCore::Core::CPUState::CalculateGDTBase(GDT);

  FEX::Windows::CallRetStack::InitializeThread(Thread);
  Thread->CurrentFrame->Pointers.ExitFunctionEC = reinterpret_cast<uintptr_t>(&ExitFunctionEC);
  CPUArea.StateFrame() = Thread->CurrentFrame;

  uint64_t EnterEC = Thread->CurrentFrame->Pointers.DispatcherLoopTopEnterEC;
  CPUArea.DispatcherLoopTopEnterEC() = EnterEC;

  uint64_t EnterECFillSRA = Thread->CurrentFrame->Pointers.DispatcherLoopTopEnterECFillSRA;
  CPUArea.DispatcherLoopTopEnterECFillSRA() = EnterECFillSRA;

  CPUArea.ContextAmd64() = {.ContextFlags = CONTEXT_CONTROL | CONTEXT_SEGMENTS | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT,
                            .AMD64_SegCs = (FEXCore::Core::CPUState::DEFAULT_USER_CS << 3) | 3,
                            .AMD64_SegDs = 0x2b,
                            .AMD64_SegEs = 0x2b,
                            .AMD64_SegFs = 0x53,
                            .AMD64_SegGs = 0x2b,
                            .AMD64_SegSs = 0x2b,
                            .AMD64_EFlags = 0x202,
                            .AMD64_MxCsr = 0x1f80,
                            .AMD64_MxCsr_copy = 0x1f80,
                            .AMD64_ControlWord = 0x27f};
  Exception::LoadStateFromECContext(Thread, CPUArea.ContextAmd64().AMD64_Context);

  Thread->FrontendPtr = new FrontendThreadData();

  {
    auto ThreadTID = GetCurrentThreadId();
    Threads.emplace(ThreadTID, Thread);
    if (StatAllocHandler) {
      Thread->ThreadStats = StatAllocHandler->AllocateSlot(ThreadTID);
    }
  }

  CPUArea.ThreadState() = Thread;
  CPUArea.Area->SuspendDoorbell = reinterpret_cast<ULONG*>(&Thread->CurrentFrame->SuspendDoorbell);
  return STATUS_SUCCESS;
#endif
}

NTSTATUS ThreadTerm(HANDLE Thread, LONG ExitCode) {
#ifdef PEAR_FEX_MEMORY_OWNER
  PearSlot::Scope PearObservation(PearSlot::Stage::ThreadTerm);
  const auto PearOriginalBody=[&]() -> NTSTATUS {
  if (!CTX || !PearSourceReady.load(std::memory_order_acquire)) return STATUS_NOT_SUPPORTED;
  if (!FEX::Windows::ValidateHandleAccess(Thread, THREAD_TERMINATE)) return STATUS_ACCESS_DENIED;
  THREAD_BASIC_INFORMATION Info {};
  if (const auto Status = NtQueryInformationThread(Thread, ThreadBasicInformation, &Info, sizeof(Info), nullptr); Status) return Status;
  if (reinterpret_cast<uintptr_t>(Info.ClientId.UniqueThread) != GetCurrentThreadId()) return STATUS_NOT_SUPPORTED;
  const auto CPUArea = GetCPUArea();
  if (!CPUArea.Area) return STATUS_NOT_SUPPORTED;
  auto* State = CPUArea.ThreadState();
  {
    std::scoped_lock Lock(ThreadCreationMutex);
    const auto It = Threads.find(GetCurrentThreadId());
    if (It == Threads.end()) return !State && !CPUArea.StateFrame() ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
    if (!State || It->second != State || CPUArea.StateFrame() != State->CurrentFrame || CPUArea.Area->InSimulation)
      return STATUS_NOT_SUPPORTED;
  }
  {
    auto Life = PearMemory::AcquireCurrentSourceLifetime(CTX.get());
    if (!Life || Life.ActualThread() != State) return STATUS_NOT_SUPPORTED;
  }
  const auto StackLimit = CPUArea.EmulatorStackLimit(), StackBase = CPUArea.EmulatorStackBase();
  const auto CurrentSP = reinterpret_cast<uintptr_t>(__builtin_frame_address(0));
  if (!StackLimit || StackLimit >= StackBase || (CurrentSP >= StackLimit && CurrentSP < StackBase)) return STATUS_NOT_SUPPORTED;
  ScopedCallbackDisable Disable;
  {
    // Remove from the original tracker under its mutex, then release that
    // mutex before source closure/owner waits. Failed cleanup retains backing.
    std::scoped_lock Lock(ThreadCreationMutex);
    const auto It = Threads.find(GetCurrentThreadId());
    if (It == Threads.end() || It->second != State) return STATUS_NOT_SUPPORTED;
    Threads.erase(It);
    if (StatAllocHandler) StatAllocHandler->DeallocateSlot(State->ThreadStats);
  }
  auto Failed = [&](const PearMemory::Result& Outcome) {
    PearRecordPrimary(Outcome);
    PearSourceReady.store(false, std::memory_order_release);
    const auto Status = PearFailureStatus(Outcome);
    PearSourceStatus.store(Status, std::memory_order_release);
    PearInitCheckpoint("ThreadTerm.refused", Outcome.Status, Outcome.ErrorDomain, Outcome.ErrorCode);
    return Status;
  };
  PearMemory::Result Outcome {};
  if (!CTX->PreparePearThreadCleanup(State, Outcome)) return Failed(Outcome);
  // Reuse upstream frontend/GDT/call-ret/CRT ownership and ordering. Check
  // native releases instead of discarding VirtualFree failures.
  const auto CallRet = FEX::Windows::CallRetStack::GetInfoThread(State);
  void* Base = reinterpret_cast<void*>(CallRet.AllocationBase); SIZE_T Bytes {};
  if (const auto Status = NtFreeVirtualMemory(NtCurrentProcess(), &Base, &Bytes, MEM_RELEASE); Status)
    return Failed({PEAR_FEX_NATIVE_FAILURE, PEAR_FEX_ERROR_NTSTATUS, static_cast<int32_t>(Status)});
  State->CallRetStackBase = nullptr;
  Base = reinterpret_cast<void*>(StackLimit); Bytes = 0;
  if (const auto Status = NtFreeVirtualMemory(NtCurrentProcess(), &Base, &Bytes, MEM_RELEASE); Status)
    return Failed({PEAR_FEX_NATIVE_FAILURE, PEAR_FEX_ERROR_NTSTATUS, static_cast<int32_t>(Status)});
#ifdef PEAR_PHASE_OBSERVE
  PearPhaseRecords.EndThread(GetCurrentThreadId(),GetFrontendThreadData(State)->PhaseLifetime);
  PearPhaseDrain();
#endif
  delete GetFrontendThreadData(State); State->FrontendPtr = nullptr;
  delete[] State->CurrentFrame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT];
  CPUArea.ThreadState() = nullptr; CPUArea.StateFrame() = nullptr;
  CPUArea.DispatcherLoopTopEnterEC() = 0; CPUArea.DispatcherLoopTopEnterECFillSRA() = 0;
  CPUArea.Area->SuspendDoorbell = nullptr;
  CPUArea.EmulatorStackLimit() = 0; CPUArea.EmulatorStackBase() = 0;
  bool Destroyed {}, Freed {};
  if (!CTX->DestroyPearThreadChecked(State, Outcome, Destroyed, Freed) || !Destroyed || !Freed) return Failed(Outcome);
  FEX::Windows::DeinitCRTThread();
  PearInitCheckpoint("ThreadTerm.complete", STATUS_SUCCESS);
  return STATUS_SUCCESS;
  };
  const auto PearReturned=PearOriginalBody();
  PearObservation.Return(1,static_cast<uint32_t>(PearReturned),0,0,PearReturned==STATUS_SUCCESS);
  return PearReturned;
#else


  if (!FEX::Windows::ValidateHandleAccess(Thread, THREAD_TERMINATE)) {
    return STATUS_ACCESS_DENIED;
  }

  auto ThreadDup = FEX::Windows::DupHandle(Thread, THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME);

  THREAD_BASIC_INFORMATION Info;
  if (auto Err = NtQueryInformationThread(*ThreadDup, ThreadBasicInformation, &Info, sizeof(Info), nullptr); Err) {
    return Err;
  }

  const auto ThreadTID = reinterpret_cast<uint64_t>(Info.ClientId.UniqueThread);
  bool Self = ThreadTID == GetCurrentThreadId();
  if (!Self) {
    CONTEXT TmpContext;
    // If we are suspending a thread that isn't ourselves, try to suspend it first so we know internal JIT locks aren't being held.
    NtSuspendThread(*ThreadDup, NULL);
    // This will wait for the thread to be suspended
    NtGetContextThread(*ThreadDup, &TmpContext);
  }

  const auto [Err, CPUArea] = GetThreadCPUArea(*ThreadDup);
  if (Err) {
    return Err;
  }

  {
    std::scoped_lock Lock(ThreadCreationMutex);
    auto it = Threads.find(ThreadTID);
    if (it == Threads.end()) {
      // Thread already terminated
      return STATUS_SUCCESS;
    }

    Threads.erase(it);
    if (StatAllocHandler) {
      StatAllocHandler->DeallocateSlot(CPUArea.ThreadState()->ThreadStats);
    }
  }
  auto ThreadState = CPUArea.ThreadState();

  delete GetFrontendThreadData(ThreadState);

  // GDT and LDT are mirrored, only free one.
  delete[] ThreadState->CurrentFrame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT];

  FEX::Windows::CallRetStack::DestroyThread(ThreadState);
  CTX->DestroyThread(ThreadState);
  ::VirtualFree(reinterpret_cast<void*>(CPUArea.EmulatorStackLimit()), 0, MEM_RELEASE);
  if (ThreadTID == GetCurrentThreadId()) {
    FEX::Windows::DeinitCRTThread();
  }

  return STATUS_SUCCESS;
#endif
}

BOOLEAN BTCpu64IsProcessorFeaturePresent(UINT Feature) {
#ifdef PEAR_FEX_MEMORY_OWNER
  if (!PearSourceReady.load(std::memory_order_acquire) || !CPUFeatures) {
    PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release); return FALSE;
  }
#endif

  return CPUFeatures->IsFeaturePresent(Feature) ? TRUE : FALSE;
}

void UpdateProcessorInformation(SYSTEM_CPU_INFORMATION* Info) {
#ifdef PEAR_FEX_MEMORY_OWNER
  if (!PearSourceReady.load(std::memory_order_acquire) || !CPUFeatures || !Info) {
    PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release); return;
  }
#endif

  CPUFeatures->UpdateInformation(Info);
}
