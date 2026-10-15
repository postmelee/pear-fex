// SPDX-License-Identifier: MIT
// Synthetic controls over the exact generated recorder and emitter includes.
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>
#include "PearThreadCreateObservation.h"
#define PEAR_PHASE_OBSERVE 1
using DWORD=uint32_t;
namespace PearMemory {
struct Result {
  uint32_t Status {},ErrorDomain {}; int32_t ErrorCode {};
  explicit operator bool() const { return Status==0; }
};
}
static bool PearPhaseOptIn=true,PearEntryObserve=true;
static uint32_t PearPhasePID=42,CurrentTid=24;
static DWORD LastError=19;
static uint32_t GetCurrentThreadId() { return CurrentTid; }
static DWORD GetLastError() { return LastError; }
static void SetLastError(DWORD e) { LastError=e; }
static std::string Emitted;
static void Sink(const char* s) { Emitted+=s; errno=77;SetLastError(88); }
static std::atomic<void(*)(const char*)> PearCheckpointSink {Sink};
static std::atomic<bool> PearSourceReady {true};
#include "PearThreadCreateRuntime.inc"

static void CheckValues() {
  static_assert(sizeof(PearAttach::Diagnostic)<=48);
  static_assert(sizeof(PearThreadCreate::Recorder)<=128);
  PearAttach::Diagnostic d;
  PearMemory::Result bad {4,2,-7},other {6,3,-8},ok {};
  const auto r=PearAttach::Capture(&d,PearAttach::Branch::RegisterInvoke,bad);
  assert(r.Status==bad.Status && r.ErrorDomain==bad.ErrorDomain && r.ErrorCode==bad.ErrorCode);
  PearAttach::Intermediate(&d,ok);
  PearAttach::Capture(&d,PearAttach::Branch::RegisterFinishIdentity,other);
  assert(d.Where==PearAttach::Branch::RegisterFinishIdentity && d.FirstFailure==PearAttach::Branch::RegisterInvoke);
  assert(d.Status==6 && d.Domain==3 && d.Code==-8 && d.IntermediateStatus==0 && (d.Flags&PearAttach::IntermediateKnown));
  d.Flags|=PearAttach::ContextKnown|PearAttach::BindingKnown;d.ContextSerial=5;d.BindingSerial=6;
  // The next helper cannot inherit a destroyed bootstrap or absent current row.
  PearAttach::ClearIdentities(&d);
  assert(!d.ContextSerial && !d.BindingSerial && !(d.Flags&3) && (d.Flags&PearAttach::IntermediateKnown));
  const auto prior=d;PearAttach::Capture(&d,PearAttach::Branch::OuterAdmission,ok);
  assert(d.Where==prior.Where && d.FirstFailure==prior.FirstFailure && d.Flags==prior.Flags &&
    d.Status==prior.Status && d.Domain==prior.Domain && d.Code==prior.Code &&
    d.IntermediateStatus==prior.IntermediateStatus && d.IntermediateDomain==prior.IntermediateDomain &&
    d.IntermediateCode==prior.IntermediateCode && d.ContextSerial==prior.ContextSerial && d.BindingSerial==prior.BindingSerial);
  assert(PearAttach::Capture<PearMemory::Result>(nullptr,PearAttach::Branch::BindCapacity,bad).Status==4);
  PearAttach::ClearIdentities(nullptr);PearAttach::Intermediate<PearMemory::Result>(nullptr,bad);
  assert(errno==11 && GetLastError()==19);
}

static void Race() {
  PearThreadCreate::Recorder recorder;std::atomic<unsigned> won {};
  std::vector<std::thread> threads;
  for (uint64_t tid=1;tid<=16;++tid) threads.emplace_back([&,tid] {
    PearThreadCreate::Record r {42,tid,100,200,300,5,4,0,0};
    r.Attach.Where=PearAttach::Branch::BindCapacity;r.Attach.FirstFailure=r.Attach.Where;
    r.Attach.Flags=PearAttach::CapacityKnown|PearAttach::NoEmptyBinding;r.Attach.Status=4;
    if (recorder.Capture(r)) ++won;
  });
  for (auto& t:threads)t.join();assert(won==1);
  unsigned taken=0;
  for (uint64_t tid=1;tid<=16;++tid) {
    PearThreadCreate::Record r;
    if (recorder.Take(42,tid,100,300,r)) { ++taken;assert(r.ThreadID==tid && r.Attach.Status==r.Status); }
  }
  assert(taken==1);
}

int main(int argc,char** argv) {
  assert(argc==2);const std::string mode=argv[1];errno=11;CheckValues();
  if (mode=="race") { Race();return 0; }
  PearMemory::Result primary {4,0,0},cleanup {6,2,-7};
  PearAttach::Diagnostic d;d.Where=d.FirstFailure=PearAttach::Branch::BindCapacity;
  d.Flags=PearAttach::CapacityKnown|PearAttach::NoEmptyBinding;d.Status=4;
  uint64_t context=0x1000,thread=0x2000,slot=reinterpret_cast<uint64_t>(&primary);
  if (mode=="both-capacity") d.Flags|=PearAttach::SerialExhausted;
  if (mode=="off") PearPhaseOptIn=false;
  if (mode=="disabled-entry") PearEntryObserve=false;
  if (mode=="mismatch") d.Status=3;
  if (mode=="max-values") {
    context=UINT64_MAX;thread=UINT64_MAX;d.Flags|=3;d.ContextSerial=d.BindingSerial=UINT64_MAX;
    d.Domain=primary.ErrorDomain=UINT32_MAX;d.Code=primary.ErrorCode=INT32_MIN;
  }
  if (mode=="earlier-stage") PearThreadCreateFailed(2,context,thread,slot,4,0,0);
  PearThreadCreateAttachFailed(context,thread,slot,primary.Status,primary.ErrorDomain,primary.ErrorCode,&d);
  if (mode=="wrong-thread") CurrentTid=25;
  if (mode=="wrong-slot") { PearMemory::Result foreign=primary;PearThreadCreateReport(reinterpret_cast<void*>(context),&foreign,cleanup,true,true); }
  else PearThreadCreateReport(reinterpret_cast<void*>(context),&primary,cleanup,true,true);
  assert(errno==11 && GetLastError()==19);
  const bool empty=mode=="off"||mode=="disabled-entry"||mode=="wrong-thread"||mode=="wrong-slot";
  if (empty) assert(Emitted.empty());
  else {
    assert(Emitted.find("PEAR_CREATE1 ")==0);
    const bool companion=mode!="mismatch"&&mode!="earlier-stage";
    assert((Emitted.find("PEAR_ATTACH1 ")!=std::string::npos)==companion);
    for (size_t start=0;start<Emitted.size();) {
      const auto end=Emitted.find('\n',start);assert(end!=std::string::npos && end-start+1<640);start=end+1;
    }
  }
  const auto first=Emitted;PearThreadCreateReport(reinterpret_cast<void*>(context),&primary,cleanup,true,true);
  if (mode=="wrong-slot") {
    // A rejected key must not consume the genuine record. The subsequent correct
    // key consumes it once; one more correct read must be silent.
    assert(first.empty() && Emitted.find("PEAR_CREATE1 ")==0 && Emitted.find("PEAR_ATTACH1 ")!=std::string::npos);
    const auto consumed=Emitted;
    PearThreadCreateReport(reinterpret_cast<void*>(context),&primary,cleanup,true,true);
    assert(Emitted==consumed);
  } else assert(Emitted==first);
  std::fputs(Emitted.c_str(),stdout);return 0;
}
