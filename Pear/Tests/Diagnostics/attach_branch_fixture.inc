// SPDX-License-Identifier: MIT
// Included in two namespaces; controlled dependencies for exact source bodies.
using Result=TestResult;
static Result Refuse(uint32_t status=PEAR_FEX_UNAVAILABLE) { return {status,0,0}; }
enum class PendingTransition { Unknown };
enum class LeaseKind { None, Active };
struct Binding {
  enum class Kind { None,Bootstrap,Thread } SourceKind {};
  const void* TEB {};uintptr_t NativeThread {};const void* SourceState {};
  const FEXCore::Context::Context* SourceContext {};
  const FEXCore::Core::InternalThreadState* AttachAttempt {};
  uint64_t Executor {},LifetimeSerial {};uint32_t Role {};
  bool Pending {},Capturing {},Unresolved {},CleanupAttempted {},LifetimeClosing {},LifetimeDeleteSealed {},CleanupOnly {};
  uint32_t LifetimeHolds {};
  PendingTransition Transition {};Result OriginalFailure {PEAR_FEX_OK,0,0},CleanupOutcome {};
  struct { LeaseKind Kind {}; } Active;
};
struct ContextLifetime {
  uint64_t Serial {9};bool Closing {},DeleteSealed {},Retained {},DestroyedBacking {};
  uint32_t Holds {};const void* CreationTEB {};uintptr_t CreationNativeThread {};
};
struct InvocationFacts { bool BridgeCalled {},ValidatedRefusal {};uint64_t CleanupCandidate {}; };
struct TestTEB { struct { void* UniqueThread {reinterpret_cast<void*>(24)}; } ClientId; };
static FEXCore::Context::Context Context;
static FEXCore::Core::InternalThreadState Thread {&Context};
static ContextLifetime Life;
static TestTEB Teb;
static Binding Bindings[PEAR_FEX_MEMORY_MAX_EXECUTORS];
static uint64_t NextLifetimeSerial=40,OwnerPID=42;
static std::atomic<bool> Configured {true};static bool BridgeDirect=true;
static int Guards=0,Admissions=0;static std::string Mode,Trace;
static bool ContextMissing=false;
struct RegistryGuard { RegistryGuard(){++Guards;} ~RegistryGuard(){--Guards;} };
static auto GetCurrentTEB() { return &Teb; }
static uint32_t CompiledSourceRole() { return PEAR_FEX_ROLE_ARM64EC; }
static ContextLifetime* ContextRecord(const FEXCore::Context::Context*) { assert(Guards);return ContextMissing?nullptr:&Life; }
static Binding* CurrentBinding() {
  assert(Guards);
  for (auto& b:Bindings) if (b.TEB==&Teb && b.NativeThread==24)return &b;
  return nullptr;
}
static void Fill() {
  for (size_t i=0;i<PEAR_FEX_MEMORY_MAX_EXECUTORS;++i) { Bindings[i]={};Bindings[i].TEB=reinterpret_cast<void*>(100+i); }
}
static Result NewAdmission() {
  assert(!Guards);Trace+='A';++Admissions;
  if ((Mode=="outer-admission" && Admissions==1)||(Mode=="bind-admission" && Admissions==2)||
      (Mode=="register-admission" && Admissions==3))return {4,3,-17};
  if (Admissions==2 && Mode=="bootstrap-capacity")Fill();
  if (Admissions==3 && Mode=="register-no-binding")Bindings[0]={};
  if (Admissions==3 && Mode=="register-no-context")ContextMissing=true;
  return Refuse(PEAR_FEX_OK);
}
namespace Retirement {
static void PoisonSourceAdmission(Result r) { Trace+="P"+std::to_string(r.Status); }
}
static pear_fex_memory_request Request(uint32_t op) { pear_fex_memory_request q {};q.opcode=op;return q; }
static Result Invoke(const pear_fex_memory_request& q,pear_fex_memory_response& r,InvocationFacts* facts) {
  assert(!Guards && q.opcode==PEAR_FEX_EXECUTOR_REGISTER);Trace+='I';
  facts->BridgeCalled=true;facts->ValidatedRefusal=Mode=="invoke-capacity";
  facts->CleanupCandidate=(Mode=="invoke-cleanup-ok"||Mode=="invoke-cleanup-fail"||Mode=="shape")?7:0;
  r.executor_id=Mode=="shape"?0:7;r.flags=PEAR_FEX_NATIVE_IDLE;
  if (Mode=="finish-identity"||Mode=="finish-prior")Bindings[0].Pending=false;
  if (Mode=="invoke-capacity"||Mode=="invoke-cleanup-ok"||Mode=="invoke-cleanup-fail"||Mode=="finish-prior")return {4,2,-19};
  return Refuse(PEAR_FEX_OK);
}
static bool NoTargetFacts(const pear_fex_memory_response&) { return true; }
static Result ResponseShapeFailure(uint32_t) { Trace+='S';return {6,0,0}; }
static Result CheckedUnregister(uint64_t value,InvocationFacts* f) {
  assert(!Guards && value==7);Trace+='C';f->BridgeCalled=true;
  return Mode=="invoke-cleanup-fail"?Result{7,1,-21}:Refuse(PEAR_FEX_OK);
}
static Result FinishTransition(const Binding&,Result primary) {
  assert(!Guards);Trace+='F';return Mode=="idle-finish"?Result{6,0,0}:primary;
}
static Result ObserveRegisteredIdle(const Binding&) {
  assert(!Guards);Trace+='O';return Mode=="idle-fail"?Result{4,3,-20}:Refuse(PEAR_FEX_OK);
}
static Result UnregisterExecutor() {
  assert(!Guards);Trace+='U';
  if (Mode=="unregister-fail")return {4,3,-18};
  Bindings[0].Executor=0;
  if (Mode=="transfer-invalid")Life.Closing=true;
  return Refuse(PEAR_FEX_OK);
}
struct SourceLifecycle {
  static Result AttachAllocatedThread(const FEXCore::Context::Context*,FEXCore::Core::InternalThreadState*,uint32_t);
};
static void Reset(const std::string& mode) {
  Mode=mode;Trace.clear();Guards=Admissions=0;Life={};ContextMissing=false;
  Thread.CTX=&Context;Thread.BaseFrameState.Thread=&Thread;Thread.CurrentFrame=mode=="invalid"?nullptr:&Thread.BaseFrameState;
  for (auto& b:Bindings)b={};NextLifetimeSerial=40;OwnerPID=42;BridgeDirect=true;Configured=true;
  if (mode=="capacity-empty"||mode=="capacity-both")Fill();
  if (mode=="capacity-serial"||mode=="capacity-both")NextLifetimeSerial=UINT64_MAX;
  if (mode=="bind-unconfigured")Configured=false;
  if (mode=="bind-no-context")ContextMissing=true;
  if (mode=="bind-closed-context")Life.Closing=true;
  if (mode=="existing-prior"||mode=="existing-state"||mode=="wrong-kind"||mode=="same-role"||
      mode=="idle-fail"||mode=="idle-finish"||mode=="idle-ok"||mode=="bootstrap-capacity"||
      mode=="unregister-fail"||mode=="transfer-invalid") {
    auto& b=Bindings[0];b.TEB=&Teb;b.NativeThread=24;b.SourceContext=&Context;b.LifetimeSerial=11;
    b.SourceKind=Binding::Kind::Bootstrap;b.SourceState=&Context;
    if (mode=="existing-prior") { b.Unresolved=true;b.OriginalFailure={4,2,-15}; }
    if (mode=="existing-state")b.Pending=true;
    if (mode=="wrong-kind")b.SourceKind=Binding::Kind::None;
    if (mode=="same-role"||mode=="idle-fail"||mode=="idle-finish"||mode=="idle-ok") {
      b.SourceKind=Binding::Kind::Thread;b.SourceState=&Thread;b.Executor=7;b.Role=mode=="same-role"?99:CompiledSourceRole();
    }
    if (mode=="unregister-fail"||mode=="transfer-invalid")b.Executor=7;
  }
}
static std::string Summary(Result r) {
  assert(!Guards);std::ostringstream s;s<<r.Status<<','<<r.ErrorDomain<<','<<r.ErrorCode<<','<<Trace<<','<<NextLifetimeSerial<<','<<Life.Closing<<','<<ContextMissing;
  for (const auto& b:Bindings)s<<';'<<(b.TEB==&Teb)<<','<<bool(b.TEB)<<','<<int(b.SourceKind)<<','<<(b.SourceState==&Thread)<<','
    <<(b.SourceState==&Context)<<','<<(b.SourceContext==&Context)<<','<<(b.AttachAttempt==&Thread)<<','<<b.Executor<<','<<b.Role<<','
    <<int(b.Transition)<<','<<b.LifetimeClosing<<','<<b.LifetimeDeleteSealed<<','<<b.LifetimeHolds<<','<<b.CleanupOnly<<','<<int(b.Active.Kind)<<','
    <<b.Pending<<','<<b.Capturing<<','<<b.Unresolved<<','<<b.LifetimeSerial<<','<<b.CleanupAttempted<<','
    <<b.OriginalFailure.Status<<','<<b.OriginalFailure.ErrorDomain<<','<<b.OriginalFailure.ErrorCode<<','
    <<b.CleanupOutcome.Status<<','<<b.CleanupOutcome.ErrorDomain<<','<<b.CleanupOutcome.ErrorCode;
  return s.str();
}
