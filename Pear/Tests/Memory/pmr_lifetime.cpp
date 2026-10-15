// SPDX-License-Identifier: MIT
// Original Pear host control. Allocation hooks are substitutes, not Wine evidence.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <list>
#include <memory>
#include <memory_resource>
#include <type_traits>
#include <unordered_map>

static void require(bool value) { if (!value) std::abort(); }
static std::unordered_map<void*, size_t> live;
static size_t allocated, freed, peak;
namespace FEXCore {
template<class T> T AlignUp(T value, T alignment) { return value + (alignment - value % alignment) % alignment; }
namespace Utils { constexpr size_t FEX_PAGE_SIZE = 4096; }
namespace Allocator {
void* VirtualAlloc(size_t size) {
  void* p=nullptr;require(posix_memalign(&p,Utils::FEX_PAGE_SIZE,size)==0);
  require(live.emplace(p,size).second);allocated++;peak=std::max(peak,live.size());return p;
}
void VirtualFree(void* p,size_t size) {
  auto it=live.find(p);require(it!=live.end() && it->second==size);
  live.erase(it);freed++;std::free(p);
}
void VirtualName(const char*,void*,size_t) {}
}
}
namespace fextl { template<class T> using list=std::list<T>; }
#define LOGMAN_THROW_A_FMT(condition, ...) require(condition)
#include "resource_under_test.inc"
using Resource=fextl::pmr::named_monotonic_page_buffer_resource;
static void release_retained() { while(!live.empty()) { auto item=*live.begin();FEXCore::Allocator::VirtualFree(item.first,item.second); } }
int main(int argc,char** argv) {
  require(argc==2);bool baseline=std::strcmp(argv[1],"baseline")==0;
  require(baseline || std::strcmp(argv[1],"candidate")==0);
#ifdef PEAR_PMR_CANDIDATE
  static_assert(!std::is_copy_constructible_v<Resource> && !std::is_move_constructible_v<Resource>);
#endif
  { Resource resource("empty"); } require(live.empty());
  { Resource resource("scope"); (void)resource.allocate(32,16);require(live.size()==1); }
  const size_t retained_after_scope=live.size();require(retained_after_scope==(baseline?1U:0U));release_retained();
  {
    Resource resource("release");(void)resource.allocate(32,16);resource.release();resource.release();require(live.empty());
    for(size_t alignment:{size_t(8),size_t(16),size_t(64),size_t(4096)}) {
      void* p=resource.allocate(31,alignment);require(reinterpret_cast<uintptr_t>(p)%alignment==0);
      std::memset(p,0x51,31);
    }
    resource.release();require(live.empty());(void)resource.allocate(8192,64);require(live.size()==1);
  }
  require(live.size()==(baseline?1U:0U));release_retained();
  for(unsigned cycle=0;cycle<32;cycle++) {
    { Resource resource("cycle");for(unsigned i=0;i<32;i++) (void)resource.allocate(512,64); }
    if(!baseline) require(live.empty());
  }
  const size_t retained_after_cycles=live.size();require(baseline?retained_after_cycles>32:retained_after_cycles==0);
  release_retained();require(live.empty() && allocated==freed);
  std::printf("{\"scope\":\"isolated_host_resource\",\"baseline\":%s,\"scope_retained_buffers\":%zu,\"cycles\":32,\"cycle_retained_buffers\":%zu,\"peak_buffers\":%zu,\"allocated\":%zu,\"freed_after_harness_cleanup\":%zu,\"wine_provider_executed\":false}\n",baseline?"true":"false",retained_after_scope,retained_after_cycles,peak,allocated,freed);
}
