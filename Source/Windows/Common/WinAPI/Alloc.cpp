// SPDX-License-Identifier: MIT
#define NTDDI_VERSION 0x0A000005
#define WINAPI
#define WINBASEAPI
#ifdef PEAR_FEX_MEMORY_OWNER
#include <FEXCore/Utils/PearDataMemory.h>
#endif

#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cerrno>
#include <winternl.h>
#include <ntstatus.h>
#include <windows.h>
#include <processenv.h>
#include "../Priv.h"

#ifndef _M_ARM64EC
namespace {
SYSTEM_BASIC_INFORMATION BasicInfo;

void InitBasicInfo() {
  NtQuerySystemInformation(SystemEmulationBasicInformation, &BasicInfo, sizeof(BasicInfo), nullptr);
}

__attribute__((used, section(".CRT$FEXH"))) void (*_InitBasicInfo)(void) = InitBasicInfo;

MEM_ADDRESS_REQUIREMENTS MakeWOW64AddressReqs() {
  MEM_ADDRESS_REQUIREMENTS Reqs {};
  Reqs.LowestStartingAddress = reinterpret_cast<void*>(BasicInfo.HighestUserAddress & ~(BasicInfo.AllocationGranularity - 1));
  return Reqs;
}
} // namespace
namespace FEX::Windows::PearCRT {
bool IsOriginalBasicInfoInitializer(uintptr_t Address) {
  return Address==reinterpret_cast<uintptr_t>(&InitBasicInfo);
}
NTSTATUS InitializeBasicInfoChecked() {
  // Preserve the real provider status and publish only complete observations.
  // The original module callback remains unchanged; the finite checked CRT
  // substitutes this typed call only for its exact original callback address.
  SYSTEM_BASIC_INFORMATION Observed {};ULONG Returned {};
  const auto Status=NtQuerySystemInformation(SystemEmulationBasicInformation,&Observed,sizeof(Observed),&Returned);
  if (Status) return Status;
  const auto Grain=Observed.AllocationGranularity;
  if (Returned!=sizeof(Observed) || Observed.PhysicalPageSize!=4096 ||
      !Grain || (Grain&(Grain-1)) || Grain<Observed.PhysicalPageSize ||
      Observed.HighestUserAddress<Observed.LowestUserAddress || Observed.HighestUserAddress<Grain)
    return STATUS_INVALID_PARAMETER;
  BasicInfo=Observed;
  return STATUS_SUCCESS;
}
} // namespace FEX::Windows::PearCRT
#endif

namespace {
#if defined(_M_ARM64EC) && defined(PEAR_FEX_MEMORY_OWNER)
MEM_ADDRESS_REQUIREMENTS MakeWOW64AddressReqs() {
  // These wrappers serve FEX's private CRT/allocators, not guest VirtualAlloc.
  // Follow the upstream low-VA preservation policy with an explicit bound:
  // a 512 MiB rpmalloc slab can otherwise fall below 4 GiB on Wine/macOS.
  MEM_ADDRESS_REQUIREMENTS Reqs {};
  Reqs.LowestStartingAddress=reinterpret_cast<void*>(UINT64_C(0x100000000));
  return Reqs;
}
#endif
NTSTATUS AllocateVirtualChecked(void*& lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
  NTSTATUS Status;
#if !defined(_M_ARM64EC) || defined(PEAR_FEX_MEMORY_OWNER)
  if (!lpAddress) {
    // Keep anonymous translator allocations outside the low guest address space.
    MEM_EXTENDED_PARAMETER ExtParam {};
    MEM_ADDRESS_REQUIREMENTS AddrReq = MakeWOW64AddressReqs();

    ExtParam.Type = MemExtendedParameterAddressRequirements;
    ExtParam.Pointer = &AddrReq;

    Status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &lpAddress, &dwSize, flAllocationType, flProtect, &ExtParam, 1);
  } else {
#endif
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &lpAddress, 0, &dwSize, flAllocationType, flProtect);
#if !defined(_M_ARM64EC) || defined(PEAR_FEX_MEMORY_OWNER)
  }
#endif
  return Status;
}
} // namespace
DLLEXPORT_FUNC(void*, VirtualAlloc, (void* lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)) {
  const auto Status=AllocateVirtualChecked(lpAddress,dwSize,flAllocationType,flProtect);
  if (Status) { SetLastError(RtlNtStatusToDosError(Status)); return nullptr; }
  return lpAddress;
}
#ifdef PEAR_FEX_MEMORY_OWNER
namespace FEXCore::Allocator {
FEXCore::Utils::PearFEXMemory::Result ReservePearData(size_t Size,bool Commit,void*& Address) {
  Address=nullptr;
  if (!Size) return {PEAR_FEX_INVALID_REQUEST,0,0};
  void* Candidate=nullptr;
  const auto Status=AllocateVirtualChecked(Candidate,Size,MEM_RESERVE|MEM_TOP_DOWN|(Commit ? MEM_COMMIT : 0),PAGE_READWRITE);
  if (Status) return {PEAR_FEX_UNAVAILABLE,PEAR_FEX_ERROR_NTSTATUS,static_cast<int32_t>(Status)};
  Address=Candidate;
  return {PEAR_FEX_OK,0,0};
}
FEXCore::Utils::PearFEXMemory::Result ReleasePearData(void* Address) {
  if (!Address) return {PEAR_FEX_INVALID_REQUEST,0,0};
  SIZE_T Size=0;
  const auto Status=NtFreeVirtualMemory(NtCurrentProcess(),&Address,&Size,MEM_RELEASE);
  if (Status) return {PEAR_FEX_UNAVAILABLE,PEAR_FEX_ERROR_NTSTATUS,static_cast<int32_t>(Status)};
  return {PEAR_FEX_OK,0,0};
}
} // namespace FEXCore::Allocator
#endif

DLLEXPORT_FUNC(SIZE_T, VirtualQuery, (LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)) {
  SIZE_T WrittenSize;
  NTSTATUS Status =
    NtQueryVirtualMemory(NtCurrentProcess(), lpAddress, MemoryBasicInformation, reinterpret_cast<void*>(lpBuffer), dwLength, &WrittenSize);
  if (Status) {
    SetLastError(RtlNtStatusToDosError(Status));
    return 0;
  }
  return WrittenSize;
}

DLLEXPORT_FUNC(WINBOOL, VirtualProtect, (void* lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)) {
  return WinAPIReturn(NtProtectVirtualMemory(NtCurrentProcess(), &lpAddress, &dwSize, flNewProtect, lpflOldProtect));
}

DLLEXPORT_FUNC(void*, VirtualAlloc2,
               (HANDLE Process, void* BaseAddress, SIZE_T Size, ULONG AllocationType, ULONG PageProtection,
                MEM_EXTENDED_PARAMETER* ExtendedParameters, ULONG ParameterCount)) {
  NTSTATUS Status;
#if !defined(_M_ARM64EC) || defined(PEAR_FEX_MEMORY_OWNER)
  if (!BaseAddress) {
    // Keep anonymous translator allocations outside the low guest address space.
    auto* NewExtParams = reinterpret_cast<MEM_EXTENDED_PARAMETER*>(alloca((ParameterCount + 1) * sizeof(MEM_EXTENDED_PARAMETER)));
    if (ExtendedParameters && ParameterCount > 0) {
      memcpy(NewExtParams, ExtendedParameters, ParameterCount * sizeof(MEM_EXTENDED_PARAMETER));
    }

    MEM_ADDRESS_REQUIREMENTS AddrReq = MakeWOW64AddressReqs();

    NewExtParams[ParameterCount].Type = MemExtendedParameterAddressRequirements;
    NewExtParams[ParameterCount].Pointer = &AddrReq;

    Status = NtAllocateVirtualMemoryEx(Process ? Process : NtCurrentProcess(), &BaseAddress, &Size, AllocationType, PageProtection,
                                       NewExtParams, ParameterCount + 1);
  } else {
#endif
    Status = NtAllocateVirtualMemoryEx(Process ? Process : NtCurrentProcess(), &BaseAddress, &Size, AllocationType, PageProtection,
                                       ExtendedParameters, ParameterCount);
#if !defined(_M_ARM64EC) || defined(PEAR_FEX_MEMORY_OWNER)
  }
#endif
  if (Status) {
    SetLastError(RtlNtStatusToDosError(Status));
    return nullptr;
  }
  return BaseAddress;
}

DLLEXPORT_FUNC(WINBOOL, VirtualFree, (void* lpAddress, SIZE_T dwSize, DWORD dwFreeType)) {
  return WinAPIReturn(NtFreeVirtualMemory(NtCurrentProcess(), &lpAddress, &dwSize, dwFreeType));
}

DLLEXPORT_FUNC(WINBOOL, FlushInstructionCache, (HANDLE hProcess, const void* lpBaseAddress, SIZE_T dwSize)) {
  return WinAPIReturn(NtFlushInstructionCache(hProcess, const_cast<void*>(lpBaseAddress), dwSize));
}

DLLEXPORT_FUNC(DWORD, FlsAlloc, (PFLS_CALLBACK_FUNCTION lpCallback)) {
  UNIMPLEMENTED();
}

DLLEXPORT_FUNC(void*, FlsGetValue, (DWORD dwFlsIndex)) {
  UNIMPLEMENTED();
}

DLLEXPORT_FUNC(WINBOOL, FlsSetValue, (DWORD dwFlsIndex, void* lpFlsData)) {
  UNIMPLEMENTED();
}

DLLEXPORT_FUNC(WINBOOL, FlsFree, (DWORD dwFlsIndex)) {
  UNIMPLEMENTED();
}

DLLEXPORT_FUNC(HLOCAL, LocalFree, (HLOCAL hMem)) {
  UNIMPLEMENTED();
}

DLLEXPORT_FUNC(DWORD, TlsAlloc, ()) {
  RtlAcquirePebLock();

  // Cannot use expansion slots or FLS here, as they would be freed before FEX can cleanup.
  DWORD Slot = RtlFindClearBitsAndSet(GetCurrentPEB()->TlsBitmap, 1, 1);
  if (Slot != -1) {
    GetCurrentTEB()->TlsSlots[Slot] = nullptr;
  }
  RtlReleasePebLock();
  return Slot;
}

DLLEXPORT_FUNC(void*, TlsGetValue, (DWORD dwTlsIndex)) {
  return GetCurrentTEB()->TlsSlots[dwTlsIndex];
}

DLLEXPORT_FUNC(WINBOOL, TlsSetValue, (DWORD dwTlsIndex, void* lpTlsValue)) {
  GetCurrentTEB()->TlsSlots[dwTlsIndex] = lpTlsValue;
  return true;
}

DLLEXPORT_FUNC(WINBOOL, TlsFree, (DWORD dwTlsIndex)) {
  RtlAcquirePebLock();

  RtlClearBits(GetCurrentPEB()->TlsBitmap, dwTlsIndex, 1);
  NTSTATUS Status = NtSetInformationThread(NtCurrentThread(), ThreadZeroTlsCell, &dwTlsIndex, sizeof(dwTlsIndex));
  RtlReleasePebLock();
  return WinAPIReturn(Status);
}
