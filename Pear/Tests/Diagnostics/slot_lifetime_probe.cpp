// SPDX-FileCopyrightText: 2026 Pear contributors
// SPDX-License-Identifier: MIT
// Exercise the actual diagnostic header/runtime/snapshot with synthetic owners.
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include "PearSlotLifetime.h"
using DWORD=uint32_t;
static DWORD LastError=87;
DWORD GetLastError() { return LastError; }
void SetLastError(DWORD x) { LastError=x; }
DWORD GetCurrentThreadId() { return 24; }
void* GetCurrentTEB() { return reinterpret_cast<void*>(0x300); }
static bool PearEntryObserve=true, PearPhaseOptIn=true;
static uint64_t PearPhasePID=42;
using PearCheckpointOutput=int(*)(const char*);
static std::vector<std::string> Lines;
static int Output(const char* p) { Lines.emplace_back(p); errno=19;LastError=91;return 0; }
static std::atomic<PearCheckpointOutput> PearCheckpointSink {Output};
#include "PearSlotLifetimeRuntime.inc"
namespace FEXCore::Utils::PearFEXMemory {
struct Binding {
  void* TEB {};void* SourceContext {};void* SourceState {};
  uint64_t LifetimeSerial {},Executor {};uint32_t LifetimeHolds {};
  bool Pending {},Capturing {},Unresolved {},CleanupAttempted {},LifetimeClosing {},LifetimeDeleteSealed {},CleanupOnly {};
};
static std::atomic<uintptr_t> Registry {};
static Binding Bindings[64] {};
static Binding* CurrentBinding() { for (auto& b:Bindings) if(b.TEB==GetCurrentTEB())return &b;return nullptr; }
}
#include "PearSlotLifetimeMemory.inc"
int main() {
  using namespace FEXCore::Utils::PearFEXMemory;
  auto& b=Bindings[0];b.TEB=GetCurrentTEB();b.SourceContext=reinterpret_cast<void*>(0x100);
  b.SourceState=reinterpret_cast<void*>(0x200);b.LifetimeSerial=9;b.Executor=7;
  const auto original=b;
  errno=5;LastError=87;
  { PearSlot::Scope s(PearSlot::Stage::Destroy,b.SourceContext,b.SourceState);
    assert(Registry.load()==0);assert(!std::memcmp(&b,&original,sizeof(b)));
    b={};s.Return(2,0,0,0,true,true,true);
  }
  assert(errno==5 && LastError==87 && Lines.size()==2);
  assert(Lines[0].find("serial=9 snapshot=1")!=std::string::npos);
  assert(Lines[1].find("serial=9 snapshot=0")!=std::string::npos);
  b=original;
  { PearSlot::Scope s(PearSlot::Stage::Destroy,b.SourceContext,b.SourceState);
    s.Return(2,3,1,-5,false,false,false); }
  assert(Lines.back().find("kind=2 status=3 domain=1 code=-5 returned=0")!=std::string::npos);
  Registry.store(0x999);
  { PearSlot::Scope s(PearSlot::Stage::Unregister);s.Return(2,3,0,0); }
  assert(Registry.load()==0x999 && Lines.back().find("snapshot=2")!=std::string::npos);
  Registry.store(0);
  { PearSlot::Scope s(PearSlot::Stage::Destroy,b.SourceContext,b.SourceState);
    b.LifetimeSerial=10;s.Return(2,3,0,0); }
  assert(Lines.back().find("serial=9 snapshot=1")!=std::string::npos);
  assert(Lines.back().find("row_serial=10")!=std::string::npos);
  const auto before=Lines.size();const auto tickets=PearSlot::NextCall.load();
  PearEntryObserve=false;
  { PearSlot::Scope s(PearSlot::Stage::Unregister);s.Return(2,0,0,0,true); }
  assert(Lines.size()==before && PearSlot::NextCall.load()==tickets);
  PearEntryObserve=true;
  { PearSlot::Scope noReturn(PearSlot::Stage::ThreadTerm); }
  for (unsigned i=0;i<600;++i) {
    PearSlot::Scope s(PearSlot::Stage::Unregister);s.Return(2,0,0,0,true);
  }
  assert(PearSlot::NextCall.load()==512);
  unsigned loss=0;for(const auto& line:Lines) {
    assert(line.size()<768);if(line.starts_with("PEAR_SLOT_LOSS1"))++loss;
    std::fputs(line.c_str(),stdout);
  }
  assert(loss==1 && Lines.size()==1024);
  assert(errno==5 && LastError==87 && Registry.load()==0);
}
