// SPDX-License-Identifier: MIT
// Original component controls for actual extracted storage helpers. No engine.
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <algorithm>
#include <cstdio>
static size_t Frees;
namespace FEXCore::Allocator { void FreePearMetadataOrHeap(void* P) { ++Frees;std::free(P); } }
#define PEAR_FEX_REQUIRE(C,...) assert(C)
#define PEAR_FEX_MEMORY_OWNER 1
#include "finite_construction_under_test.inc"
struct Observed { static inline size_t Destroyed {}; ~Observed() { ++Destroyed; } };
int main() {
  void* P=std::aligned_alloc(16,256);assert(P);
  std::weak_ptr<Observed> Weak;
  {
    auto Strong=std::allocate_shared<Observed>(PearControlAllocator<Observed>{P});
    Weak=Strong;
    auto Copy=Strong;Strong.reset();assert(!Observed::Destroyed && !Frees);
  }
  assert(Observed::Destroyed==1 && Frees==0 && Weak.expired());
  Weak.reset();assert(Frees==1);
  ARMEmitter::ForwardLabel Label;
  uint8_t Storage[80] {};
  for (size_t I=0;I<17;++I) ARMEmitter::AddLocationToLabel(&Label,{Storage+I,ARMEmitter::ForwardLabel::InstType::B});
  assert(Label.FirstInst.Location==Storage && Label.Insts.Count==16 && !Label.Insts.Overflow);
  ARMEmitter::AddLocationToLabel(&Label,{Storage+17,ARMEmitter::ForwardLabel::InstType::B});
  assert(Label.Insts.Count==16 && Label.Insts.Overflow);
  for (size_t I=0;I<16;++I) assert(Label.Insts.Items[I].Location==Storage+I+1);
  auto R=CopyCPUBrandChunk("Unknown ARM CPU",0);
  assert(!std::memcmp(&R,"Unknown ARM CPU",14));
  auto Z=CopyCPUBrandChunk("Unknown ARM CPU",16);
  const Result Empty {};assert(!std::memcmp(&Z,&Empty,sizeof(Z)));
  Z=CopyCPUBrandChunk("Unknown ARM CPU",32);assert(!std::memcmp(&Z,&Empty,sizeof(Z)));
  constexpr char Full[]="01234567890123456789012345678901234567890123456789";
  R=CopyCPUBrandChunk(Full,32);assert(!std::memcmp(&R,Full+32,16));
  puts("{\"passed\":true,\"engine_initialized\":false,\"scope\":\"actual_storage_helpers\"}");
}
