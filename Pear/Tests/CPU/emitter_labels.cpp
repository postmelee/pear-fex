// SPDX-License-Identifier: MIT
// Real FEX emitter headers; NX data only, with a host test allocator adapter.
#include <CodeEmitter/Emitter.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string_view>
static size_t Allocations;
namespace FEXCore::Allocator {
void* aligned_alloc(size_t Alignment,size_t Size) {
  void* P=nullptr;
  if (posix_memalign(&P,Alignment<sizeof(void*)?sizeof(void*):Alignment,Size)) std::abort();
  ++Allocations; return P;
}
void aligned_free(void* P) { std::free(P); }
}
namespace LogMan::Throw {
[[noreturn]] void MFmt(const char*,const fmt::format_args&) { std::exit(97); }
}
namespace LogMan::Msg { void MFmtImpl(DebugLevels,const char*,const fmt::format_args&) { std::abort(); } }
int main(int argc,char** argv) {
  alignas(16) uint32_t Bytes[1024] {};
  ARMEmitter::Emitter E;
  ARMEmitter::ForwardLabel Direct;
  E.SetBuffer(reinterpret_cast<uint8_t*>(Bytes),sizeof(Bytes));
  for (unsigned I=0;I<18;++I) assert(E.b(&Direct)==ARMEmitter::BranchEncodeSucceeded::Success);
  assert(!E.Bind(&Direct) && E.PearLabelFailure && Allocations==0);
  E.PearLabelFailure=false;
  E.SetPrivateStagingBuffer(reinterpret_cast<uint8_t*>(Bytes),sizeof(Bytes));
  ARMEmitter::ForwardLabel Private;
  for (unsigned I=0;I<256;++I) assert(E.b(&Private)==ARMEmitter::BranchEncodeSucceeded::Success);
  assert(Allocations && !Private.Insts.Overflow);
  if (argc==2 && std::string_view(argv[1])=="private-into-direct") {
    E.SetBuffer(reinterpret_cast<uint8_t*>(Bytes),sizeof(Bytes));
    (void)E.Bind(&Private);return 1;
  }
  assert(E.Bind(&Private) && !E.PearLabelFailure);
  for (unsigned I=0;I<256;++I) assert(Bytes[I]==(0x14000000U|(256-I)));
  const auto Before=Allocations;
  E.SetBuffer(reinterpret_cast<uint8_t*>(Bytes),sizeof(Bytes));
  ARMEmitter::ForwardLabel Reset;
  for (unsigned I=0;I<18;++I) assert(E.b(&Reset)==ARMEmitter::BranchEncodeSucceeded::Success);
  assert(!E.Bind(&Reset) && Allocations==Before);
  std::puts("{\"passed\":true,\"private_branches_bound\":256,\"direct_allocation_count\":0,\"generated_code_executed\":false}");
}
