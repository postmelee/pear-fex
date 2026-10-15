// SPDX-License-Identifier: MIT
// Original Pear bounded wrapper around the pinned FEX CRT/rpmalloc mechanism.
// Callback order is from Source/Windows/Common/CRT/CRT.cpp (MIT). No historical
// initializer, table symbol, source policy, service ABI or wire is replaced.
#include <FEXCore/Utils/AllocatorHooks.h>
#define __WINESRC__
#include "CheckedCRT.h"
#include "PearEmptyInitProof.h"
#include "Common/FEXUnixLib.h"
#include "Common/Priv.h"
#include "Common/CRT/PearCheckedEnvironment.h"
#include <FEXCore/Utils/PearFEXMemory.h>
#include <rpmalloc/rpmalloc.h>
#include <limits>
#include <cstring>
#include <ntstatus.h>
#include <winbase.h>
#include <sysinfoapi.h>
#include <initializer_list>

namespace FEX::Windows::PearCRT {
bool IsOriginalBasicInfoInitializer(uintptr_t);
NTSTATUS InitializeBasicInfoChecked();
}

extern "C" {
extern void (*FEXA)(),(*FEXZ)(),(*XIA)(),(*XIZ)(),(*XCA)(),(*XCZ)();
extern void (*XLA)(HINSTANCE,DWORD,LPVOID*),(*XLZ)(HINSTANCE,DWORD,LPVOID*);
extern void (*__CTOR_LIST__[])();
extern uint64_t _tls_index;
}
namespace FEX::Windows::PearEmptyInit {
namespace {
constexpr size_t MAX_QUERY_REGIONS=256,MAX_ENVIRONMENT_WCHARS=32768,MAX_TLS_INDEX=1024;
struct Image { uintptr_t Base {}; size_t Size {}; const IMAGE_NT_HEADERS64* NT {}; };
Outcome Good(Phase P) { return {Status::OK,P,Domain::None,0,0,0}; }
Outcome Refused(Phase P) { return {Status::Unavailable,P,Domain::None,0,0,0}; }
Outcome Bad(Phase P) { return {Status::Invalid,P,Domain::None,0,0,0}; }
Outcome NTFailure(Phase P,NTSTATUS S) { return {Status::NativeFailure,P,Domain::NTStatus,static_cast<int32_t>(S),0,0}; }
bool Add(uintptr_t Start,size_t Size,uintptr_t& End) {
  if (Size>std::numeric_limits<uintptr_t>::max()-Start) return false;
  End=Start+Size;return true;
}
bool Readable(ULONG Protection) {
  if (Protection&(PAGE_GUARD|PAGE_NOACCESS)) return false;
  const auto Basic=Protection&0xff;
  return Basic==PAGE_READONLY || Basic==PAGE_READWRITE || Basic==PAGE_WRITECOPY ||
    Basic==PAGE_EXECUTE_READ || Basic==PAGE_EXECUTE_WRITECOPY;
}
Outcome Observe(uintptr_t Start,size_t Size,Phase P,void* ImageBase=nullptr,bool Executable=false) {
  uintptr_t End {};
  if (!Start || !Size || !Add(Start,Size,End)) return Bad(P);
  size_t Regions {};
  while (Start<End) {
    if (++Regions>MAX_QUERY_REGIONS) return Refused(P);
    MEMORY_BASIC_INFORMATION M {}; SIZE_T Returned {};
    const auto S=NtQueryVirtualMemory(NtCurrentProcess(),reinterpret_cast<void*>(Start),MemoryBasicInformation,&M,sizeof(M),&Returned);
    if (S) return NTFailure(P,S);
    uintptr_t RegionEnd {};
    if (Returned!=sizeof(M) || M.State!=MEM_COMMIT || !Readable(M.Protect) ||
        (ImageBase && (M.AllocationBase!=ImageBase || M.Type!=MEM_IMAGE)) ||
        (Executable && M.Protect!=PAGE_EXECUTE_READ) ||
        reinterpret_cast<uintptr_t>(M.BaseAddress)>Start || !M.RegionSize ||
        !Add(reinterpret_cast<uintptr_t>(M.BaseAddress),M.RegionSize,RegionEnd) || RegionEnd<=Start) return Bad(P);
    Start=RegionEnd<End ? RegionEnd : End;
  }
  return Good(P);
}
Outcome ImageSpan(const Image& I,uintptr_t Address,size_t Size,Phase P,bool Code=false) {
  if (Address<I.Base || Size>I.Size || Address-I.Base>I.Size-Size) return Bad(P);
  return Observe(Address,Size,P,reinterpret_cast<void*>(I.Base),Code);
}
Outcome InspectImage(Image& I) {
  void* Base {};
  if (!RtlPcToFileHeader(reinterpret_cast<void*>(&InspectImage),&Base) || !Base) return Refused(Phase::Image);
  const auto B=reinterpret_cast<uintptr_t>(Base);
  auto R=Observe(B,sizeof(IMAGE_DOS_HEADER),Phase::Image,Base);if (!R) return R;
  const auto DOS=reinterpret_cast<const IMAGE_DOS_HEADER*>(B);
  if (DOS->e_magic!=IMAGE_DOS_SIGNATURE || DOS->e_lfanew<sizeof(IMAGE_DOS_HEADER) || DOS->e_lfanew>4096) return Bad(Phase::Image);
  uintptr_t NTAddress {};if (!Add(B,static_cast<size_t>(DOS->e_lfanew),NTAddress)) return Bad(Phase::Image);
  R=Observe(NTAddress,sizeof(IMAGE_NT_HEADERS64),Phase::Image,Base);if (!R) return R;
  const auto NT=reinterpret_cast<const IMAGE_NT_HEADERS64*>(NTAddress);
  if (NT->Signature!=IMAGE_NT_SIGNATURE || NT->FileHeader.Machine!=IMAGE_FILE_MACHINE_ARM64 ||
      NT->FileHeader.SizeOfOptionalHeader!=sizeof(IMAGE_OPTIONAL_HEADER64) ||
      NT->OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
      !NT->OptionalHeader.SizeOfImage || NT->OptionalHeader.SizeOfImage>128*1024*1024 ||
      NT->FileHeader.NumberOfSections>96 || !NT->FileHeader.NumberOfSections ||
      NT->OptionalHeader.NumberOfRvaAndSizes!=IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return Bad(Phase::Image);
  I={B,NT->OptionalHeader.SizeOfImage,NT};
  R=ImageSpan(I,NTAddress,sizeof(*NT),Phase::Image);if (!R) return R;
  // Actual ordinary ARM64/static target and CHPE absence are independently
  // verified by the build reader before root admission. This runtime image
  // check does not claim a new ARM64EC classifier.
  return Good(Phase::Image);
}
Outcome Append(CRTPlan& P,const Image& I,uintptr_t Address,CRTPlan::Kind K) {
  if (!Address) return Good(Phase::Image);
  if (P.Count==CRTPlan::MAX_CALLBACKS) return Refused(Phase::Image);
  const auto R=ImageSpan(I,Address,4,Phase::Image,true);if (!R) return R;
  P.Entries[P.Count++]={Address,K};return Good(Phase::Image);
}
Outcome Table(CRTPlan& P,const Image& I,uintptr_t Begin,uintptr_t End,CRTPlan::Kind K) {
  if (!Begin || !End || (Begin&7) || End<Begin || ((End-Begin)&7) ||
      End-Begin>CRTPlan::MAX_CALLBACKS*sizeof(uintptr_t) || Begin<I.Base ||
      Begin-I.Base>I.Size || End<I.Base || End-I.Base>I.Size) return Bad(Phase::Image);
  if (Begin==End) return Good(Phase::Image);
  const auto R=ImageSpan(I,Begin,End-Begin,Phase::Image);if (!R) return R;
  for (auto A=Begin;A<End;A+=sizeof(uintptr_t)) {
    const auto Added=Append(P,I,*reinterpret_cast<const uintptr_t*>(A),K);if (!Added) return Added;
  }
  return Good(Phase::Image);
}
Outcome GNU(CRTPlan& P,const Image& I) {
  // Reuse the actual linker-owned __CTOR_LIST__[1] start. There is no invented
  // __CTOR_END__ symbol or unbounded terminator walk. The current mapped PE
  // section supplies the actual end bound, independently matched to link bytes.
  const auto Start=reinterpret_cast<uintptr_t>(&__CTOR_LIST__[1]);
  const auto Sections=reinterpret_cast<const IMAGE_SECTION_HEADER*>(
    reinterpret_cast<const std::byte*>(I.NT)+offsetof(IMAGE_NT_HEADERS64,OptionalHeader)+I.NT->FileHeader.SizeOfOptionalHeader);
  const auto Count=I.NT->FileHeader.NumberOfSections;
  auto R=ImageSpan(I,reinterpret_cast<uintptr_t>(Sections),Count*sizeof(IMAGE_SECTION_HEADER),Phase::Image);if (!R) return R;
  uintptr_t End {};
  for (unsigned N=0;N<Count;++N) {
    const auto& S=Sections[N];uintptr_t B {},E {};
    if (!Add(I.Base,S.VirtualAddress,B) || !Add(B,S.Misc.VirtualSize,E) || E<I.Base || E-I.Base>I.Size) return Bad(Phase::Image);
    if (Start>=B && Start<E) { if (End) return Bad(Phase::Image);End=E; }
  }
  if (!End || Start>End || (Start&7)) return Bad(Phase::Image);
  uintptr_t Entries[CRTPlan::MAX_CALLBACKS] {};size_t Used {};
  for (auto A=Start;A<End;) {
    if (End-A<sizeof(uintptr_t) || Used==CRTPlan::MAX_CALLBACKS) return Refused(Phase::Image);
    R=ImageSpan(I,A,sizeof(uintptr_t),Phase::Image);if (!R) return R;
    const auto Entry=*reinterpret_cast<const uintptr_t*>(A);
    if (!Entry) {
      // Pinned upstream runs GNU callbacks in reverse.
      while (Used) { R=Append(P,I,Entries[--Used],CRTPlan::Kind::GNU);if (!R) return R; }
      return Good(Phase::Image);
    }
    Entries[Used++]=Entry;A+=sizeof(uintptr_t);
  }
  return Refused(Phase::Image);
}
Outcome TLS(const Image& I,Report& R) {
  const auto& D=I.NT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
  if (!D.VirtualAddress && !D.Size) {
    // The pinned FEX CRT uses dynamic TLS through its original Windows API
    // wrappers. An absent PE static-TLS directory is admissible only when the
    // actual image has no static-TLS section and no TLS callback to invoke.
    const auto Sections=reinterpret_cast<const IMAGE_SECTION_HEADER*>(
      reinterpret_cast<const std::byte*>(I.NT)+offsetof(IMAGE_NT_HEADERS64,OptionalHeader)+I.NT->FileHeader.SizeOfOptionalHeader);
    auto O=ImageSpan(I,reinterpret_cast<uintptr_t>(Sections),
      I.NT->FileHeader.NumberOfSections*sizeof(IMAGE_SECTION_HEADER),Phase::TLS);if (!O) return O;
    for (unsigned N=0;N<I.NT->FileHeader.NumberOfSections;++N)
      if (!std::memcmp(Sections[N].Name,".tls",4) && Sections[N].Misc.VirtualSize) return Refused(Phase::TLS);
    const auto Begin=reinterpret_cast<uintptr_t>(&XLA),End=reinterpret_cast<uintptr_t>(&XLZ);
    if (!Begin || End<Begin || (End-Begin)%sizeof(uintptr_t) ||
        End-Begin>CRTPlan::MAX_CALLBACKS*sizeof(uintptr_t)) return Bad(Phase::TLS);
    if (Begin!=End) {
      O=ImageSpan(I,Begin,End-Begin,Phase::TLS);if (!O) return O;
      for (auto A=Begin;A<End;A+=sizeof(uintptr_t)) if (*reinterpret_cast<const uintptr_t*>(A)) return Refused(Phase::TLS);
    }
    // Records a verified TLS prerequisite, including verified absence. It does
    // not claim that a static TLS block was allocated or observed.
    R.TLSObserved=1;return Good(Phase::TLS);
  }
  if (!D.VirtualAddress || D.Size!=sizeof(IMAGE_TLS_DIRECTORY64)) return Bad(Phase::TLS);
  uintptr_t Address {};if (!Add(I.Base,D.VirtualAddress,Address)) return Bad(Phase::TLS);
  auto O=ImageSpan(I,Address,sizeof(IMAGE_TLS_DIRECTORY64),Phase::TLS);if (!O) return O;
  const auto& T=*reinterpret_cast<const IMAGE_TLS_DIRECTORY64*>(Address);
  if (T.AddressOfIndex!=reinterpret_cast<uintptr_t>(&_tls_index) || T.EndAddressOfRawData<T.StartAddressOfRawData ||
      T.EndAddressOfRawData-T.StartAddressOfRawData>65536 || !T.StartAddressOfRawData || !T.AddressOfIndex) return Bad(Phase::TLS);
  O=ImageSpan(I,T.StartAddressOfRawData,T.EndAddressOfRawData-T.StartAddressOfRawData,Phase::TLS);if (!O) return O;
  O=ImageSpan(I,T.AddressOfIndex,sizeof(_tls_index),Phase::TLS);if (!O) return O;
  const auto Index=_tls_index;if (Index>=MAX_TLS_INDEX) return Refused(Phase::TLS);
  const auto TEB=GetCurrentTEB();
  O=Observe(reinterpret_cast<uintptr_t>(TEB),sizeof(*TEB),Phase::TLS);if (!O) return O;
  const auto Vector=reinterpret_cast<uintptr_t>(TEB->ThreadLocalStoragePointer);
  uintptr_t Slot {};if (!Vector || !Add(Vector,Index*sizeof(uintptr_t),Slot)) return Bad(Phase::TLS);
  O=Observe(Slot,sizeof(uintptr_t),Phase::TLS);if (!O) return O;
  const auto Block=*reinterpret_cast<const uintptr_t*>(Slot);if (!Block) return Bad(Phase::TLS);
  const auto Bytes=T.EndAddressOfRawData-T.StartAddressOfRawData+T.SizeOfZeroFill;
  if (!Bytes || Bytes>65536) return Refused(Phase::TLS);
  O=Observe(Block,Bytes,Phase::TLS);if (!O) return O;
  R.TLSObserved=1;return Good(Phase::TLS);
}
struct PEBLock {
  PEBLock() { RtlAcquirePebLock(); }
  ~PEBLock() { RtlReleasePebLock(); }
};
Outcome Environment(uint64_t& ExpectedPID,const wchar_t** ObservedEnvironment=nullptr,size_t* ObservedCharacters=nullptr) {
  const auto TEB=GetCurrentTEB();
  auto R=Observe(reinterpret_cast<uintptr_t>(TEB),sizeof(*TEB),Phase::Environment);if (!R) return R;
  const auto PEB=TEB->Peb;
  R=Observe(reinterpret_cast<uintptr_t>(PEB),sizeof(*PEB),Phase::Environment);if (!R) return R;
  const auto Params=reinterpret_cast<const RTL_USER_PROCESS_PARAMETERS64*>(PEB->ProcessParameters);
  R=Observe(reinterpret_cast<uintptr_t>(Params),sizeof(*Params),Phase::Environment);if (!R) return R;
  const auto Env=reinterpret_cast<const wchar_t*>(Params->Environment);if (!Env) return Bad(Phase::Environment);
  constexpr wchar_t PIDName[]=L"PEAR_FEX_MEMORY_OWNER_PID=";
  bool Found {};size_t Cursor {},Lines {},ObservedRegions {};uintptr_t ObservedEnd {};
  while (Cursor<MAX_ENVIRONMENT_WCHARS) {
    const auto Begin=Cursor;
    for (;;) {
      if (Cursor==MAX_ENVIRONMENT_WCHARS) return Refused(Phase::Environment);
      const auto Address=reinterpret_cast<uintptr_t>(Env+Cursor);uintptr_t Next {};
      if (!Add(Address,sizeof(wchar_t),Next)) return Bad(Phase::Environment);
      if (Next>ObservedEnd) {
        if (++ObservedRegions>MAX_QUERY_REGIONS) return Refused(Phase::Environment);
        MEMORY_BASIC_INFORMATION M {};SIZE_T Returned {};
        const auto S=NtQueryVirtualMemory(NtCurrentProcess(),reinterpret_cast<void*>(Address),
                                         MemoryBasicInformation,&M,sizeof(M),&Returned);
        if (S) return NTFailure(Phase::Environment,S);
        if (Returned!=sizeof(M) || M.State!=MEM_COMMIT || !Readable(M.Protect) ||
            reinterpret_cast<uintptr_t>(M.BaseAddress)>Address || !M.RegionSize ||
            !Add(reinterpret_cast<uintptr_t>(M.BaseAddress),M.RegionSize,ObservedEnd) || Next>ObservedEnd) return Bad(Phase::Environment);
      }
      if (!Env[Cursor]) break;
      ++Cursor;
    }
    if (Cursor==Begin) {
      // The preceding entry's NUL plus this actual NUL closes a double-NUL
      // environment; an empty environment has no required PID and refuses.
      if (!Found) return Refused(Phase::Environment);
      if (ObservedEnvironment) *ObservedEnvironment=Env;
      if (ObservedCharacters) *ObservedCharacters=Cursor+1;
      return Good(Phase::Environment);
    }
    if (++Lines>256) return Refused(Phase::Environment);
    const auto Len=Cursor-Begin;
    if (Len>=4 && Env[Begin]==L'F' && Env[Begin+1]==L'E' && Env[Begin+2]==L'X' && Env[Begin+3]==L'_') return Refused(Phase::Environment);
    constexpr auto Prefix=sizeof(PIDName)/sizeof(wchar_t)-1;
    if (Len>=Prefix && !std::memcmp(Env+Begin,PIDName,Prefix*sizeof(wchar_t))) {
      if (Found || Len==Prefix || Len-Prefix>10) return Bad(Phase::UnixPID);
      uint64_t PID {};
      for (auto A=Begin+Prefix;A<Cursor;++A) {
        const auto Digit=Env[A];if (Digit<L'0' || Digit>L'9' || (A==Begin+Prefix && Digit==L'0')) return Bad(Phase::UnixPID);
        PID=PID*10+Digit-L'0';if (PID>UINT32_MAX) return Bad(Phase::UnixPID);
      }
      ExpectedPID=PID;Found=true;
    }
    ++Cursor;
  }
  return Refused(Phase::Environment);
}
Outcome UnixPID(CRTPlan& P,Report& R,uint64_t Expected) {
  auto Name=InitUnicodeString(L"ntdll.dll");HMODULE NtDll {};
  auto S=LdrGetDllHandle(nullptr,0,&Name,&NtDll);if (S) return NTFailure(Phase::UnixPID,S);
  STRING Symbol=InitAnsiString("__wine_unix_call_dispatcher");void* Address {};
  S=LdrGetProcedureAddress(NtDll,&Symbol,0,&Address);if (S) return NTFailure(Phase::UnixPID,S);
  if (!Address) return Refused(Phase::UnixPID);
  auto O=Observe(reinterpret_cast<uintptr_t>(Address),sizeof(void*),Phase::UnixPID,NtDll);if (!O) return O;
  const auto Dispatcher=*reinterpret_cast<decltype(FEX::Windows::UnixLib::UnixCallDispatcher)*>(Address);
  if (!Dispatcher) return Refused(Phase::UnixPID);
  // Reuse the exact source-selected eight-service native library name. This
  // direct stack-only load avoids the old Init formatted log before rpmalloc.
  auto Library=InitUnicodeString(L"libwow64fex");uint64_t Loaded[2] {};
  S=NtQueryVirtualMemory(NtCurrentProcess(),&Library,MemoryWineLoadUnixLibByName,Loaded,sizeof(Loaded),nullptr);
  if (S) return NTFailure(Phase::UnixPID,S);
  if (!Loaded[0] || !Loaded[1]) return Refused(Phase::UnixPID);
  FEXUnixLib_GetPID Actual {};
  S=Dispatcher(static_cast<unixlib_handle_t>(Loaded[1]),static_cast<uint32_t>(FEXUnixLibFunctions::GetPID),&Actual);
  if (S) return NTFailure(Phase::UnixPID,S);
  if (!Expected || !Actual.Result || Actual.Result!=Expected) return Bad(Phase::UnixPID);
  // No Windows GetCurrentProcessId fallback and no fabricated pid.
  P.NtDll=NtDll;P.NativeOwnerPID=Actual.Result;
  FEX::Windows::UnixLib::UnixLibHandle=Loaded[1];FEX::Windows::UnixLib::UnixCallDispatcher=Dispatcher;
  R.UnixPIDObserved=1;return Good(Phase::UnixPID);
}
Outcome Owner(CRTPlan& P,Report& R) {
  namespace Memory=FEXCore::Utils::PearFEXMemory;
  auto Convert=[](Memory::Result V,Phase At) -> Outcome {
    return V ? Good(At) : Outcome {Status::OwnerFailure,At,Domain::OwnerWire,V.ErrorCode,V.Status,V.ErrorDomain};
  };
  const auto Initialized=Memory::Init(P.NtDll,P.NativeOwnerPID);
  if (!Initialized) return Convert(Initialized,Phase::Owner);
  Memory::Result Released;bool Attempted {};
  const auto Prepared=Memory::PrepareOwnerMetadata(P.Metadata,Released,Attempted);
  // This is pre-construction owner cleanup. The same record also preserves a
  // later failed Thread construction cleanup; both happen before final cleanup.
  if (Attempted) {
    R.ConstructionCleanupAttempted=1;
    R.ConstructionCleanup=Convert(Released,Phase::Cleanup);
    R.Cleanup=R.ConstructionCleanup;
  }
  if (!Prepared) return Convert(Prepared,Phase::Owner);
  if (!Attempted || !Released) return Attempted ? Convert(Released,Phase::Cleanup) : Refused(Phase::Cleanup);
  STRING Name=InitAnsiString("__wine_pear_fex_memory");void* Symbol {};
  const auto S=LdrGetProcedureAddress(P.NtDll,&Name,0,&Symbol);if (S) return NTFailure(Phase::Owner,S);
  if (!Symbol) return Refused(Phase::Owner);
  using Bridge=uint32_t(WINAPI*)(const pear_fex_memory_request*,pear_fex_memory_response*);
  pear_fex_memory_request Q {};pear_fex_memory_response A {};
  Q.version=PEAR_FEX_MEMORY_VERSION;Q.size=sizeof(Q);Q.opcode=PEAR_FEX_QUERY;Q.owner_pid=P.NativeOwnerPID;
  const auto Actual=reinterpret_cast<Bridge>(Symbol)(&Q,&A);
  if (Actual!=A.status || A.version!=PEAR_FEX_MEMORY_VERSION || A.size!=sizeof(A) || A.reserved0) return Bad(Phase::Owner);
  if (Actual!=PEAR_FEX_OK) {
    if (Actual>PEAR_FEX_QUARANTINED || A.owner_pid || A.flags || A.allocation_class || A.ec_role ||
        A.allocation_id || A.generation || A.write_epoch || A.executor_id || A.continuation_id || A.extent_offset || A.extent_size ||
        A.private_write_base || A.lifecycle_state || A.effective_protection || A.capabilities ||
        A.native_error_domain>PEAR_FEX_ERROR_MACH || (!A.native_error_domain && A.native_error_code)) return Bad(Phase::Owner);
    return {Status::OwnerFailure,Phase::Owner,Domain::OwnerWire,A.native_error_code,Actual,A.native_error_domain};
  }
  if (A.owner_pid!=P.NativeOwnerPID || A.flags || A.native_error_domain || A.native_error_code || A.allocation_class || A.ec_role ||
      A.allocation_id || A.generation || A.write_epoch || A.executor_id || A.continuation_id || A.extent_offset || A.extent_size ||
      A.private_write_base || A.lifecycle_state || A.effective_protection ||
      A.capabilities!=(PEAR_FEX_SINGLE_MAP_JIT|PEAR_FEX_OBSERVED_4K|PEAR_FEX_GLOBAL_GATE)) return Bad(Phase::Owner);
  // This is ordinary native backing proof only. Exact DLL/caller grant is a
  // separate compiled/root gate; capability8 and hybrid support are not inferred.
  R.OwnerObserved=1;return Good(Phase::Owner);
}
Outcome InvokeCallbacks(CRTPlan& P,CRTPlan::Kind K,DWORD Reason,Report& R) {
  for (size_t N=0;N<P.Count;++N) if (P.Entries[N].Group==K) {
    ++R.CallbackAttempts;
    if (K==CRTPlan::Kind::FEX && PearCRT::IsOriginalEnvironmentInitializer(P.Entries[N].Address)) {
      R.EnvironmentCheckedAttempted=1;
      const auto E=PearCRT::InitializeEnvironmentChecked(P.Environment,P.EnvironmentCharacters);
      ++R.CallbackReturns; // The typed helper returned even when its outcome refuses.
      R.EnvironmentCheckedReturned=1;R.EnvironmentStatus=static_cast<uint32_t>(E.Status);
      R.EnvironmentNativeStatus=E.NativeStatus;R.EnvironmentPublished=E.Published;
      R.EnvironmentEnvAllocated=E.EnvAllocated;R.EnvironmentArrayAllocated=E.ArrayAllocated;
      R.EnvironmentEnvFreeAttempted=E.EnvFreeAttempted;R.EnvironmentEnvFreeReturned=E.EnvFreeReturned;
      R.EnvironmentArrayFreeAttempted=E.ArrayFreeAttempted;R.EnvironmentArrayFreeReturned=E.ArrayFreeReturned;
      if (!E) return E.NativeStatus ? NTFailure(Phase::Environment,E.NativeStatus) :
        Outcome {E.Status==PearCRT::EnvironmentStatus::AllocationFailure ? Status::AllocationFailure : Status::Unavailable,
                 Phase::Environment,Domain::None,0,0,0};
      if (!E.Published) return Refused(Phase::Environment);
      continue; // Already counted this actual typed return exactly once.
    } else if (K==CRTPlan::Kind::FEX && PearCRT::IsOriginalBasicInfoInitializer(P.Entries[N].Address)) {
      const auto Actual=PearCRT::InitializeBasicInfoChecked();
      ++R.CallbackReturns;
      if (Actual) return NTFailure(Phase::CRTProcess,Actual);
      continue;
    } else if (K==CRTPlan::Kind::XL) {
      reinterpret_cast<void(*)(HINSTANCE,DWORD,LPVOID*)>(P.Entries[N].Address)(nullptr,Reason,nullptr);
      ++R.TLSCallbacks;
    } else reinterpret_cast<void(*)()>(P.Entries[N].Address)();
    ++R.CallbackReturns;
  }
  return Good(Phase::CRTProcess);
}
} // namespace

Outcome ObserveHostBasics(uint32_t& ProcessorCount,uint32_t& PageSize) {
  ProcessorCount=0;PageSize=0;
  if (!Proof::Ready()) return Refused(Phase::Proof);
  SYSTEM_BASIC_INFORMATION Basic {};ULONG Returned {};
  const auto S=NtQuerySystemInformation(SystemBasicInformation,&Basic,sizeof(Basic),&Returned);
  if (S) return NTFailure(Phase::HostBasics,S);
  const auto Count=static_cast<uint8_t>(Basic.NumberOfProcessors);
  if (Returned!=sizeof(Basic) || !Count ||
      Basic.PhysicalPageSize!=4096) return Refused(Phase::HostBasics);
  SYSTEM_INFO Actual {};GetSystemInfo(&Actual);
  if (Actual.dwPageSize!=Basic.PhysicalPageSize || Actual.dwNumberOfProcessors!=Count ||
      Actual.wProcessorArchitecture!=PROCESSOR_ARCHITECTURE_ARM64) return Refused(Phase::HostBasics);
  ProcessorCount=Actual.dwNumberOfProcessors;PageSize=Actual.dwPageSize;return Good(Phase::HostBasics);
}

Outcome InspectBeforeInitialization(CRTPlan& P,Report& R) {
  if (!Proof::Ready()) return Refused(Phase::Proof);
  const auto Observed=InspectPrerequisites(P,R);
  if (!Observed) return Observed;
  // Private finite-image bounds. Root admission must match the linked image,
  // compiler stack ledger, native provider and current signing before this
  // closed source selection can be opened. Never reuse another process's facts.
  constexpr uint64_t LinkedPEMetadata=22*4096;
  constexpr uint64_t ConcurrentMetadata=12*4096;
  constexpr uint64_t RequiredAdditionalViews=4; // Two splits, at most two each.
  uint64_t Total {};
  const auto Budget=FEXCore::Utils::PearFEXMemory::AssessMetadataBudget(
    P.Metadata,P.NativeOwnerPID,RequiredAdditionalViews,
    LinkedPEMetadata+ConcurrentMetadata,Total);
  if (!Budget) return {Status::OwnerFailure,Phase::Owner,Domain::OwnerWire,
                       Budget.ErrorCode,Budget.Status,Budget.ErrorDomain};
  if (!Total || Total>PEAR_FEX_MEMORY_METADATA_BYTES) return Refused(Phase::Proof);
  return Observed;
}
Outcome InspectPrerequisites(CRTPlan& P,Report& R) {
  Image I;auto O=InspectImage(I);if (!O) return O;
  P.CurrentImage=reinterpret_cast<HMODULE>(I.Base);
  // Every original callback and current TLS/environment observation is checked
  // before rpmalloc or any constructor. No arbitrary callback list is supplied.
  O=Table(P,I,reinterpret_cast<uintptr_t>(&FEXA),reinterpret_cast<uintptr_t>(&FEXZ),CRTPlan::Kind::FEX);if (!O) return O;
  O=GNU(P,I);if (!O) return O;
  O=Table(P,I,reinterpret_cast<uintptr_t>(&XIA),reinterpret_cast<uintptr_t>(&XIZ),CRTPlan::Kind::XI);if (!O) return O;
  O=Table(P,I,reinterpret_cast<uintptr_t>(&XCA),reinterpret_cast<uintptr_t>(&XCZ),CRTPlan::Kind::XC);if (!O) return O;
  O=Table(P,I,reinterpret_cast<uintptr_t>(&XLA),reinterpret_cast<uintptr_t>(&XLZ),CRTPlan::Kind::XL);if (!O) return O;
  size_t EnvironmentInitializers {};
  for (size_t N=0;N<P.Count;++N) if (P.Entries[N].Group==CRTPlan::Kind::FEX &&
      PearCRT::IsOriginalEnvironmentInitializer(P.Entries[N].Address)) ++EnvironmentInitializers;
  if (EnvironmentInitializers!=1) return Refused(Phase::Environment);
  size_t BasicInfoInitializers {};
  for (size_t N=0;N<P.Count;++N) if (P.Entries[N].Group==CRTPlan::Kind::FEX &&
      PearCRT::IsOriginalBasicInfoInitializer(P.Entries[N].Address)) ++BasicInfoInitializers;
  if (BasicInfoInitializers!=1) return Refused(Phase::CRTProcess);
  O=TLS(I,R);if (!O) return O;
  uint64_t PID {};
  { PEBLock Locked;O=Environment(PID,&P.Environment,&P.EnvironmentCharacters);if (!O) return O; }
  O=UnixPID(P,R,PID);if (!O) return O;
  return Owner(P,R);
}
Outcome InitializeCheckedProcess(CRTPlan& P,Report& R) {
  if (!Proof::Ready() || !P.CurrentImage || !P.NativeOwnerPID || !R.OwnerObserved || !R.TLSObserved || P.ProcessReturned) return Refused(Phase::CRTProcess);
  PEBLock Locked;uint64_t PID {};const wchar_t* Env {};size_t Characters {};
  auto O=Environment(PID,&Env,&Characters);
  if (!O || PID!=P.NativeOwnerPID || Env!=P.Environment || Characters!=P.EnvironmentCharacters) return O ? Bad(Phase::UnixPID) : O;
  // RtlAcquirePebLock is source-recursive. The original InitEnv callback takes
  // that same lock; immutable owned environment is preserved through its scan.
  R.CRTProcessAttempted=1;
  const auto Actual=rpmalloc_initialize(nullptr);
  if (Actual) return {Status::RPMallocFailure,Phase::CRTProcess,Domain::RPMallocReturn,Actual,0,0};
  if (!rpmalloc_is_thread_initialized()) return Refused(Phase::CRTProcess);
  for (const auto Kind : {CRTPlan::Kind::FEX,CRTPlan::Kind::GNU,CRTPlan::Kind::XI,CRTPlan::Kind::XC,CRTPlan::Kind::XL}) {
    O=InvokeCallbacks(P,Kind,DLL_PROCESS_ATTACH,R);if (!O) return O;
  }
  P.ProcessReturned=true;R.CRTProcessReturned=1;return Good(Phase::CRTProcess);
}
Outcome InitializeCheckedThread(CRTPlan& P,Report& R) {
  if (!Proof::Ready() || !P.ProcessReturned || P.ThreadReturned) return Refused(Phase::CRTThread);
  R.CRTThreadAttempted=1;rpmalloc_thread_initialize();
  if (!rpmalloc_is_thread_initialized()) return Refused(Phase::CRTThread);
  const auto O=InvokeCallbacks(P,CRTPlan::Kind::XL,DLL_THREAD_ATTACH,R);if (!O) return O;
  P.ThreadReturned=true;R.CRTThreadReturned=1;return Good(Phase::CRTThread);
}
Outcome FinalizeCheckedThread(CRTPlan& P,Report& R) {
  if (!P.ThreadReturned) return Refused(Phase::Cleanup);
  // The caller must have confirmed actual source Context/Thread deletion first.
  // Refused/unknown cleanup retains the allocator/TLS, never destroys backing.
  if ((R.ContextCreated && (!R.ContextDestroyed || !R.ContextAllocatorCompleted)) ||
      (R.ThreadCreated && (!R.ThreadDestroyed || !R.ThreadAllocatorCompleted))) return Refused(Phase::Cleanup);
  const auto O=InvokeCallbacks(P,CRTPlan::Kind::XL,DLL_THREAD_DETACH,R);if (!O) return O;
  rpmalloc_thread_finalize();
  if (rpmalloc_is_thread_initialized()) return Refused(Phase::Cleanup);
  P.ThreadReturned=false;R.ThreadCRTFinalized=1;return Good(Phase::Cleanup);
}
} // namespace FEX::Windows::PearEmptyInit
