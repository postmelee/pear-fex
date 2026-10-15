// SPDX-License-Identifier: MIT
// Actual allocation helper bodies with substituted NT providers, not Wine/engine execution.
#include <FEXCore/Utils/PearFEXMemory.h>
#include <cstdint>
#include <cstdio>
using NTSTATUS=int32_t;
using SIZE_T=size_t;
using DWORD=uint32_t;
constexpr DWORD MEM_RESERVE=0x2000,MEM_COMMIT=0x1000,MEM_TOP_DOWN=0x100000,MEM_RELEASE=0x8000,PAGE_READWRITE=4;
constexpr int MemExtendedParameterAddressRequirements=1;
struct MEM_ADDRESS_REQUIREMENTS {void* LowestStartingAddress;};
struct MEM_EXTENDED_PARAMETER {int Type;void* Pointer;};
static unsigned Calls,Freed,Errors;
static DWORD SeenFlags;
static NTSTATUS ProviderStatus;
static void* const Base=reinterpret_cast<void*>(uintptr_t{0x120000000});
static void* NtCurrentProcess(){return reinterpret_cast<void*>(intptr_t{-1});}
static MEM_ADDRESS_REQUIREMENTS MakeWOW64AddressReqs(){return {reinterpret_cast<void*>(uintptr_t{0x100000000})};}
static NTSTATUS NtAllocateVirtualMemoryEx(void* Process,void** Address,size_t* Size,DWORD Flags,DWORD Protect,MEM_EXTENDED_PARAMETER* Params,unsigned Count){
  ++Calls;SeenFlags=Flags;
  if(Process!=NtCurrentProcess() || *Address || *Size!=8192 || Protect!=PAGE_READWRITE || Count!=1 || !Params || Params->Type!=MemExtendedParameterAddressRequirements || static_cast<MEM_ADDRESS_REQUIREMENTS*>(Params->Pointer)->LowestStartingAddress!=reinterpret_cast<void*>(uintptr_t{0x100000000})) ++Errors;
  *Address=Base; // A failed provider may have modified its local output.
  return ProviderStatus;
}
static NTSTATUS NtAllocateVirtualMemory(void* Process,void** Address,uintptr_t ZeroBits,size_t* Size,DWORD Flags,DWORD Protect){
  ++Calls;SeenFlags=Flags;
  if(Process!=NtCurrentProcess() || *Address || ZeroBits || *Size!=8192 || Protect!=PAGE_READWRITE) ++Errors;
  *Address=Base;return ProviderStatus;
}
static NTSTATUS NtFreeVirtualMemory(void* Process,void** Address,size_t* Size,DWORD Flags){
  ++Freed;
  if(Process!=NtCurrentProcess() || *Address!=Base || *Size || Flags!=MEM_RELEASE) ++Errors;
  *Address=nullptr;return ProviderStatus;
}
#include "checked_data_memory_under_test.inc"
int main(){
  using namespace FEXCore::Allocator;
  void* Address=Base;unsigned Passed=0;
  auto Result=ReservePearData(0,false,Address);
  if(Result || Result.Status!=PEAR_FEX_INVALID_REQUEST || Address || Calls) return 1;
  ++Passed;
  for(bool Commit:{false,true}){
    ProviderStatus=static_cast<int32_t>(0xc0000017);Address=Base;
    Result=ReservePearData(8192,Commit,Address);
    if(Result || Result.ErrorDomain!=PEAR_FEX_ERROR_NTSTATUS || Result.ErrorCode!=ProviderStatus || Address || SeenFlags!=(MEM_RESERVE|MEM_TOP_DOWN|(Commit ? MEM_COMMIT : 0))) return 2;
    ++Passed;
    ProviderStatus=0;Result=ReservePearData(8192,Commit,Address);
    if(!Result || Address!=Base || Result.ErrorDomain || Result.ErrorCode) return 3;
    ++Passed;
  }
  ProviderStatus=static_cast<int32_t>(0xc000000d);
  Result=ReleasePearData(Address);
  if(Result || Result.ErrorDomain!=PEAR_FEX_ERROR_NTSTATUS || Result.ErrorCode!=ProviderStatus || Address!=Base || Freed!=1) return 4;
  ++Passed;
  ProviderStatus=0;Result=ReleasePearData(Address);
  if(!Result || Result.ErrorDomain || Result.ErrorCode || Address!=Base || Freed!=2) return 5;
  ++Passed;
  Result=ReleasePearData(nullptr);
  if(Result || Result.Status!=PEAR_FEX_INVALID_REQUEST || Freed!=2 || Errors || Calls!=4) return 6;
  ++Passed;
  std::printf("{\"cases\":%u,\"passed\":true,\"provider\":\"substituted\",\"engine_initialized\":false}\n",Passed);
}
