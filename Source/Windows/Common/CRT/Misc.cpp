// SPDX-License-Identifier: MIT
#define _SECIMP
#define _CRTIMP
#include <cstdlib>
#include <cstdint>
#include <unistd.h>
#include <wchar.h>
#include <windef.h>
#include <winternl.h>
#include <winbase.h>
#include "../Priv.h"
#ifdef PEAR_FEX_MEMORY_OWNER
#include "PearCheckedEnvironment.h"
#endif

namespace {
char* Env;
char** EnvArray;
} // namespace

namespace {
void InitEnv() {
  RtlAcquirePebLock();
  auto ProcessParams = reinterpret_cast<RTL_USER_PROCESS_PARAMETERS64*>(NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters);
  wchar_t* EnvW = reinterpret_cast<wchar_t*>(ProcessParams->Environment);
  DWORD SizeW = 4;
  // The PEB environment is terminated by two null wchars.
  for (wchar_t* It = EnvW; It[0] != 0 || It[1] != 0; It++, SizeW += 2)
    ;
  DWORD Size;
  RtlUnicodeToMultiByteSize(&Size, EnvW, SizeW);
  Env = reinterpret_cast<char*>(RtlAllocateHeap(GetProcessHeap(), 0, Size + 1));
  RtlUnicodeToMultiByteN(Env, Size + 1, nullptr, EnvW, SizeW);

  size_t EnvCount = 0;
  char* It = Env;
  while (*It) {
    EnvCount++;
    It += strlen(It) + 1;
  }

  EnvArray = reinterpret_cast<char**>(RtlAllocateHeap(GetProcessHeap(), 0, (EnvCount + 1) * sizeof(char*)));

  It = Env;
  for (size_t i = 0; i < EnvCount; i++) {
    EnvArray[i] = It;
    It += strlen(It) + 1;
  }
  EnvArray[EnvCount] = nullptr;

  RtlReleasePebLock();
}

__attribute__((used, section(".CRT$FEXB"))) void (*_InitEnv)(void) = InitEnv;
} // namespace

#ifdef PEAR_FEX_MEMORY_OWNER
namespace FEX::Windows::PearCRT {
bool IsOriginalEnvironmentInitializer(uintptr_t Address) { return Address==reinterpret_cast<uintptr_t>(&InitEnv); }
EnvironmentOutcome InitializeEnvironmentChecked(const wchar_t* Expected,size_t Characters) {
  EnvironmentOutcome O;
  if (!Expected || Characters<2 || Characters>32768 || Env || EnvArray) return O;
  struct Lock { Lock() { RtlAcquirePebLock(); } ~Lock() { RtlReleasePebLock(); } } Locked;
  const auto Parameters=reinterpret_cast<RTL_USER_PROCESS_PARAMETERS64*>(NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters);
  const auto Actual=reinterpret_cast<const wchar_t*>(Parameters->Environment);
  if (Actual!=Expected) { O.Status=EnvironmentStatus::Invalid;return O; }
  const auto Start=reinterpret_cast<uintptr_t>(Actual);
  const size_t WideBytes=Characters*sizeof(wchar_t);
  if (Start>UINTPTR_MAX-WideBytes) { O.Status=EnvironmentStatus::Invalid;return O; }
  const auto End=Start+WideBytes;
  size_t Regions {};
  for (auto Cursor=Start;Cursor<End;) {
    if (++Regions>256) return O;
    MEMORY_BASIC_INFORMATION M {};SIZE_T Returned {};
    const auto S=NtQueryVirtualMemory(NtCurrentProcess(),reinterpret_cast<void*>(Cursor),MemoryBasicInformation,&M,sizeof(M),&Returned);
    if (S) { O.Status=EnvironmentStatus::NativeFailure;O.NativeStatus=static_cast<int32_t>(S);return O; }
    const auto B=reinterpret_cast<uintptr_t>(M.BaseAddress);const auto Basic=M.Protect&0xff;
    if (Returned!=sizeof(M) || M.State!=MEM_COMMIT || (M.Protect&(PAGE_GUARD|PAGE_NOACCESS)) ||
        !(Basic==PAGE_READONLY || Basic==PAGE_READWRITE || Basic==PAGE_WRITECOPY || Basic==PAGE_EXECUTE_READ) ||
        B>Cursor || !M.RegionSize || B>UINTPTR_MAX-M.RegionSize || B+M.RegionSize<=Cursor) {
      O.Status=EnvironmentStatus::Invalid;return O;
    }
    Cursor=B+M.RegionSize<End ? B+M.RegionSize : End;
  }
  // Match the actual double-NUL span, not a guessed SizeW or unchecked walk.
  if (Actual[Characters-1] || Actual[Characters-2]) { O.Status=EnvironmentStatus::Invalid;return O; }
  size_t WideEntries {};
  for (size_t I=0;I<Characters-1;) {
    if (!Actual[I]) { if (I!=Characters-2) { O.Status=EnvironmentStatus::Invalid;return O; }break; }
    if (++WideEntries>256) return O;
    while (I<Characters && Actual[I]) ++I;
    if (I>=Characters-1) { O.Status=EnvironmentStatus::Invalid;return O; }
    ++I;
  }
  DWORD Bytes {};
  // The pinned MinGW declaration lacks const; the paired Wine implementation
  // only reads this locked, validated input while computing the output size.
  auto S=RtlUnicodeToMultiByteSize(&Bytes,const_cast<wchar_t*>(Actual),static_cast<DWORD>(WideBytes));
  O.ConversionSizeReturned=true;
  if (S) { O.Status=EnvironmentStatus::ConversionFailure;O.NativeStatus=static_cast<int32_t>(S);return O; }
  if (Bytes<2 || Bytes>65536) return O;
  const auto Heap=GetProcessHeap();if (!Heap) return O;
  auto* Temporary=reinterpret_cast<char*>(RtlAllocateHeap(Heap,0,static_cast<size_t>(Bytes)+1));
  if (!Temporary) { O.Status=EnvironmentStatus::AllocationFailure;return O; }
  O.EnvAllocated=true;char** Array {};
  const auto Fail=[&](EnvironmentStatus Why,int32_t Native=0) {
    O.Status=Why;O.NativeStatus=Native;
    if (Array) { O.ArrayFreeAttempted=true;O.ArrayFreeReturned=RtlFreeHeap(Heap,0,Array)!=FALSE; }
    O.EnvFreeAttempted=true;O.EnvFreeReturned=RtlFreeHeap(Heap,0,Temporary)!=FALSE;
    // Preserve the primary conversion/allocation status. A failed free is
    // independently observed; no errno or NTSTATUS is invented for BOOLEAN.
    return O;
  };
  ULONG Produced {};
  S=RtlUnicodeToMultiByteN(Temporary,Bytes,&Produced,Actual,static_cast<DWORD>(WideBytes));
  O.ConversionReturned=true;
  if (S) return Fail(EnvironmentStatus::ConversionFailure,static_cast<int32_t>(S));
  if (Produced!=Bytes || Temporary[Bytes-1] || Temporary[Bytes-2]) return Fail(EnvironmentStatus::Invalid);
  Temporary[Bytes]=0;
  size_t Count {},Cursor {};
  while (Cursor<Bytes-1) {
    if (!Temporary[Cursor]) { if (Cursor!=Bytes-2) return Fail(EnvironmentStatus::Invalid);break; }
    if (++Count>256) return Fail(EnvironmentStatus::Unavailable);
    while (Cursor<Bytes && Temporary[Cursor]) ++Cursor;
    if (Cursor>=Bytes-1) return Fail(EnvironmentStatus::Invalid);
    ++Cursor;
  }
  if (Count!=WideEntries) return Fail(EnvironmentStatus::Invalid);
  Array=reinterpret_cast<char**>(RtlAllocateHeap(Heap,0,(Count+1)*sizeof(char*)));
  if (!Array) return Fail(EnvironmentStatus::AllocationFailure);
  O.ArrayAllocated=true;Cursor=0;
  for (size_t I=0;I<Count;++I) {
    Array[I]=Temporary+Cursor;
    while (Cursor<Bytes && Temporary[Cursor]) ++Cursor;
    if (Cursor>=Bytes) return Fail(EnvironmentStatus::Invalid);
    ++Cursor;
  }
  Array[Count]=nullptr;
  // Publish only the genuine completed buffers. Failed conversion/allocation
  // never replaces global environ with incomplete or null backing.
  Env=Temporary;EnvArray=Array;O.Published=true;O.Status=EnvironmentStatus::OK;return O;
}
}
#endif

DLLEXPORT_FUNC(char***, __p__environ, ()) {
  return &EnvArray;
}

char* getenv(const char* VarName) {
  size_t VarNameLen = strlen(VarName);
  char* It = Env;
  char* Ret = nullptr;

  while (*It) {
    char* Eq = strchr(It, '=');
    if (Eq && Eq - It == VarNameLen && !strncmp(It, VarName, VarNameLen)) {
      Ret = Eq + 1;
      break;
    }

    It += strlen(It) + 1;
  }

  return Ret;
}

int atexit(void (*)(void)) {
  return 0;
}

#pragma push_macro("abort")
#undef abort
void abort(void) {
  UNIMPLEMENTED();
}
#pragma pop_macro("abort")

int getpid(void) {
  return static_cast<int>(GetCurrentProcessId());
}

void exit(int _Code) {
  UNIMPLEMENTED();
}

DLLEXPORT_FUNC(void, _assert, (const char* message, const char* file, unsigned line)) {
  UNIMPLEMENTED();
}

DLLEXPORT_FUNC(
  uintptr_t, _beginthreadex,
  (void* security, unsigned stack_size, unsigned(__stdcall* start_address)(void*), void* arglist, unsigned initflag, unsigned* thrdaddr)) {
  UNIMPLEMENTED();
}

DLLEXPORT_FUNC(int*, __sys_nerr, (void)) {
  UNIMPLEMENTED();
}
