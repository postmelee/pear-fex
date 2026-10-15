// SPDX-License-Identifier: MIT
// Exact original and prepared function bodies with controlled native dependencies.
#include <atomic>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <wine/pear_fex_memory.h>
#include "PearAttachObservation.h"
namespace FEXCore::Context { class Context {}; }
namespace FEXCore::Core { struct InternalThreadState { const FEXCore::Context::Context* CTX; struct Frame { InternalThreadState* Thread {}; } BaseFrameState;Frame* CurrentFrame {}; }; }
struct TestResult { uint32_t Status {PEAR_FEX_UNAVAILABLE},ErrorDomain {};int32_t ErrorCode {};explicit operator bool() const {return Status==PEAR_FEX_OK;} };
namespace Original {
#include "attach_branch_fixture.inc"
#include "original-attach-functions.inc"
}
namespace Observed {
#include "attach_branch_fixture.inc"
#include "observed-attach-functions.inc"
}
int main() {
  struct Case { const char* Name;uint16_t Branch; };
  const Case cases[]={
    {"success",0},{"invalid",1},{"outer-admission",2},{"existing-prior",3},{"existing-state",4},{"wrong-kind",4},
    {"same-role",5},{"idle-fail",6},{"idle-finish",6},{"idle-ok",0},{"unregister-fail",7},{"transfer-invalid",8},
    {"bind-admission",9},{"bind-unconfigured",10},{"bind-no-context",10},{"bind-closed-context",10},
    {"capacity-empty",12},{"capacity-serial",12},{"capacity-both",12},{"bootstrap-capacity",12},
    {"register-admission",13},{"register-no-binding",14},{"register-no-context",14},
    {"invoke-capacity",15},{"invoke-cleanup-ok",15},{"invoke-cleanup-fail",15},{"shape",16},
    {"finish-identity",17},{"finish-prior",17}
  };
  for (auto c:cases) {
    Original::Reset(c.Name);auto a=Original::SourceLifecycle::AttachAllocatedThread(&Original::Context,&Original::Thread,Original::CompiledSourceRole());
    const auto expected=Original::Summary(a);
    Observed::Reset(c.Name);auto b=Observed::SourceLifecycle::AttachAllocatedThread(&Observed::Context,&Observed::Thread,Observed::CompiledSourceRole());
    assert(Observed::Summary(b)==expected);
    Observed::Reset(c.Name);PearAttach::Diagnostic d {};
    auto r=Observed::AttachAllocatedThreadObserved(&Observed::Context,&Observed::Thread,Observed::CompiledSourceRole(),&d);
    assert(Observed::Summary(r)==expected && uint16_t(d.Where)==c.Branch);
    if (!r)assert(d.Status==r.Status && d.Domain==r.ErrorDomain && d.Code==r.ErrorCode);
    if (std::string(c.Name)=="bootstrap-capacity")assert(!(d.Flags&PearAttach::BindingKnown) && d.BindingSerial==0);
    if (std::string(c.Name)=="register-no-binding")assert(!(d.Flags&3) && d.ContextSerial==0 && d.BindingSerial==0);
    if (std::string(c.Name)=="register-no-context")assert(!(d.Flags&PearAttach::ContextKnown) && d.ContextSerial==0);
    if (std::string(c.Name)=="capacity-both")assert((d.Flags&192)==192);
    if (std::string(c.Name)=="finish-prior")assert(d.FirstFailure==PearAttach::Branch::RegisterInvoke && d.IntermediateStatus==4);
    std::cout<<c.Name<<" parity=1 branch="<<uint16_t(d.Where)<<'\n';
  }
  // The matching-row refusal compares the full result and side effects, including null output.
  Original::Reset("success");Observed::Reset("success");
  Original::Bindings[0].TEB=&Original::Teb;Original::Bindings[0].NativeThread=24;Original::Bindings[0].Pending=true;Original::Bindings[0].LifetimeSerial=11;
  Observed::Bindings[0].TEB=&Observed::Teb;Observed::Bindings[0].NativeThread=24;Observed::Bindings[0].Pending=true;Observed::Bindings[0].LifetimeSerial=11;
  auto a=Original::BindActual(&Original::Context,&Original::Thread,Original::Binding::Kind::Thread);
  const auto expected=Original::Summary(a);
  auto null=Observed::BindActual(&Observed::Context,&Observed::Thread,Observed::Binding::Kind::Thread);
  assert(Observed::Summary(null)==expected);
  Observed::Reset("success");
  Observed::Bindings[0].TEB=&Observed::Teb;Observed::Bindings[0].NativeThread=24;Observed::Bindings[0].Pending=true;Observed::Bindings[0].LifetimeSerial=11;
  PearAttach::Diagnostic d;auto b=Observed::BindActual(&Observed::Context,&Observed::Thread,Observed::Binding::Kind::Thread,&d);
  assert(Observed::Summary(b)==expected && d.Where==PearAttach::Branch::BindExistingIdentity);
  std::cout<<"bind-existing parity=1 branch=11\n";
}
