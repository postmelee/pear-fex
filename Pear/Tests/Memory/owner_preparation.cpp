// SPDX-License-Identifier: MIT
// Actual pre-engine preparation body with substituted bridge/provider calls.
#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include "wine/pear_fex_memory.h"
struct Result {
 uint32_t Status {PEAR_FEX_UNAVAILABLE},ErrorDomain {};int32_t ErrorCode {};
 explicit operator bool() const { return Status==PEAR_FEX_OK; }
};
static Result Refuse(uint32_t S=PEAR_FEX_UNAVAILABLE) {return {S,0,0};}
static std::atomic<bool> Configured {true};static bool BridgeDirect=true;static uint64_t OwnerPID=21;
static uint32_t Role=PEAR_FEX_ROLE_NATIVE;static uint32_t CompiledSourceRole(){return Role;}
struct Context {const void* Object {};};static Context ContextLifetimes[1];
struct Binding {const void* TEB {};};static Binding Bindings[1];
struct RegistryGuard {};
struct InvocationFacts {bool BridgeCalled {},ValidatedRefusal {};uint64_t CleanupCandidate {};};
static int Registered,Observed,Unregistered,Poisoned;
static Result RegisterResult,ObserveResult,CleanupResult;static bool ValidRefusal,HasCandidate,BadShape;
namespace Retirement {static void PoisonSourceAdmission(Result R) { assert(!R);++Poisoned; }}
static Result ResponseShapeFailure(uint32_t Op) {assert(Op==PEAR_FEX_EXECUTOR_REGISTER);auto R=Refuse(PEAR_FEX_VERSION_MISMATCH);Retirement::PoisonSourceAdmission(R);return R;}
static bool NoTargetFacts(const pear_fex_memory_response&) {return !BadShape;}
static pear_fex_memory_request Request(uint32_t Op){pear_fex_memory_request Q {};Q.version=3;Q.size=128;Q.opcode=Op;Q.owner_pid=OwnerPID;return Q;}
static Result Invoke(const pear_fex_memory_request& Q,pear_fex_memory_response& R,InvocationFacts* F){
 assert(Q.opcode==PEAR_FEX_EXECUTOR_REGISTER && Q.ec_role==PEAR_FEX_ROLE_NATIVE && Q.owner_pid==21);
 ++Registered;F->BridgeCalled=true;F->ValidatedRefusal=ValidRefusal;F->CleanupCandidate=HasCandidate?42:0;
 R.executor_id=HasCandidate?42:0;R.flags=PEAR_FEX_NATIVE_IDLE;return RegisterResult;
}
static Result ObserveMetadata(pear_fex_memory_metadata& M){++Observed;M.owner_pid=21;M.fixed_native_bytes=108564;return ObserveResult;}
static Result CheckedUnregister(uint64_t ID){assert(ID==42);++Unregistered;return CleanupResult;}
#include "owner_preparation_under_test.inc"
static void Reset(){
 Configured=true;BridgeDirect=true;OwnerPID=21;Role=PEAR_FEX_ROLE_NATIVE;
 ContextLifetimes[0]={};Bindings[0]={};Registered=Observed=Unregistered=Poisoned=0;
 RegisterResult=ObserveResult=CleanupResult=Refuse(PEAR_FEX_OK);ValidRefusal=BadShape=false;HasCandidate=true;
}
int main(){
 pear_fex_memory_metadata M {};Result C;bool Attempted;
 for(int I=0;I<5;++I){Reset();if(I==0)Configured=false;if(I==1)BridgeDirect=false;if(I==2)Role=PEAR_FEX_ROLE_ARM64EC;if(I==3)ContextLifetimes[0].Object=&M;if(I==4)Bindings[0].TEB=&M;
  assert(!PrepareOwnerMetadata(M,C,Attempted));assert(!Registered&&!Observed&&!Unregistered&&!Attempted&&!M.owner_pid);}
 Reset();RegisterResult={PEAR_FEX_NATIVE_FAILURE,PEAR_FEX_ERROR_ERRNO,12};HasCandidate=false;ValidRefusal=true;
 auto R=PrepareOwnerMetadata(M,C,Attempted);assert(!R&&R.ErrorCode==12&&!Attempted&&!Observed&&!Unregistered&&!Poisoned);
 Reset();BadShape=true;R=PrepareOwnerMetadata(M,C,Attempted);assert(!R&&R.Status==PEAR_FEX_VERSION_MISMATCH&&Attempted&&C&&Unregistered==1&&!Observed&&Poisoned);
 Reset();RegisterResult=Refuse(PEAR_FEX_VERSION_MISMATCH);HasCandidate=false;
 R=PrepareOwnerMetadata(M,C,Attempted);assert(!R&&!Attempted&&!Unregistered&&Poisoned);
 Reset();ObserveResult={PEAR_FEX_NATIVE_FAILURE,PEAR_FEX_ERROR_ERRNO,5};
 R=PrepareOwnerMetadata(M,C,Attempted);assert(!R&&R.ErrorCode==5&&Attempted&&C&&Unregistered==1&&!M.owner_pid);
 Reset();ObserveResult={PEAR_FEX_NATIVE_FAILURE,PEAR_FEX_ERROR_ERRNO,5};CleanupResult={PEAR_FEX_NATIVE_FAILURE,PEAR_FEX_ERROR_ERRNO,16};
 R=PrepareOwnerMetadata(M,C,Attempted);assert(!R&&R.ErrorCode==5&&Attempted&&!C&&C.ErrorCode==16&&Poisoned&&!M.owner_pid);
 Reset();CleanupResult={PEAR_FEX_NATIVE_FAILURE,PEAR_FEX_ERROR_ERRNO,16};
 R=PrepareOwnerMetadata(M,C,Attempted);assert(R&&Attempted&&!C&&Poisoned&&!M.owner_pid);
 Reset();R=PrepareOwnerMetadata(M,C,Attempted);assert(R&&Attempted&&C&&Registered==1&&Observed==1&&Unregistered==1&&!Poisoned&&M.owner_pid==21);
 puts("PASS: actual owner preparation preserves registration/observation/cleanup outcomes and refuses existing source lifetimes");
}
