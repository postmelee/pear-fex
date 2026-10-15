// SPDX-License-Identifier: MIT
// Actual selected GuestToHostMap with Wine VM and FEX/rpmalloc allocation.
// Ordinary MinGW CRT fixture; no FEX engine/ARM64EC initialization or guest execution.
#include <FEXCore/fextl/memory.h>
#include "Interface/Core/LookupCache.h"
#include <rpmalloc/rpmalloc.h>
#include <windows.h>
#include <cstdio>
#include <cstring>

namespace {
struct Region { const void* Base; size_t Size; };
Region Regions[32];
unsigned Count;
bool Capture;
void require(bool value, unsigned step) {
  if (!value) {
    std::printf("{\"record_kind\":\"pear_guest_map_failure\",\"step\":%u,\"win32_error\":%lu}\n", step, GetLastError());
    std::fflush(stdout); ExitProcess(step);
  }
}
void record_region(const void* address, size_t size) {
  require(address && size && Count < 32, 31);
  for (unsigned i = 0; i < Count; ++i) require(Regions[i].Base != address, 32);
  Regions[Count++] = {address, size};
}
void observe_name(const char* name, const void* address, size_t size) {
  if (Capture && name && std::strcmp(name, "FEXMem_BlockLinks") == 0) record_region(address, size);
}
void no_thp(const void*, size_t, FEXCore::Allocator::THPControl) {}
void check_regions(bool released) {
  for (unsigned i = 0; i < Count; ++i) {
    MEMORY_BASIC_INFORMATION info {};
    require(VirtualQuery(Regions[i].Base, &info, sizeof(info)) == sizeof(info), 41);
    require(info.State == (released ? MEM_FREE : MEM_COMMIT), 42);
    if (released) require(info.AllocationBase == nullptr, 43);
    else require(info.AllocationBase == Regions[i].Base && info.Protect == PAGE_READWRITE && info.RegionSize >= Regions[i].Size, 44);
  }
}
}
// Link boundary is deliberately unavailable. Empty-map ClearCache must never
// invoke it; populated destruction does not delink or pretend to retire code.
namespace FEXCore::CPU::PearJITLinks {
FEXCore::Utils::PearFEXMemory::Result Queue(Ticket) {
  require(false, 91); return {PEAR_FEX_UNAVAILABLE, 0, 0};
}
}
int main() {
  SYSTEM_INFO system {}; GetSystemInfo(&system);
  require(system.dwPageSize == 4096, 11);
  require(rpmalloc_initialize(nullptr) == 0, 12);
  FEXCore::Allocator::SetupHooks(system.dwPageSize, {observe_name, no_thp});
  for (unsigned cycle = 0; cycle < 2; ++cycle) {
    Count = 0; Capture = true;
    {
      FEXCore::GuestToHostMap map;
      if (cycle == 1) {
        // Observe ClearCache's actual empty-map path; no fabricated link tickets.
        Capture = false;
        { auto lock = map.AcquireWriteLock(); map.ClearCache(lock); }
        require(map.BlockLinks->empty(), 21);
        Count = 0;
        MEMORY_BASIC_INFORMATION info {};
        require(VirtualQuery(map.BlockLinks, &info, sizeof(info)) == sizeof(info), 22);
        record_region(info.AllocationBase, info.RegionSize);
        Capture = true;
      }
      { auto lock = map.AcquireWriteLock();
        for (uint64_t i = 0; i < 128; ++i) {
          const FEXCore::GuestToHostMap::BlockLinkTag key {i, nullptr};
          require(map.BlockLinks->emplace(key, FEXCore::CPU::PearJITLinks::Ticket {}).second, 23);
        }
        require(map.BlockLinks->size() == 128, 24);
      }
      require(Count >= 2, 25); check_regions(false);
    }
    Capture = false; check_regions(true);
    std::printf("{\"record_kind\":\"pear_guest_map_lifetime\",\"cycle\":%u,\"nodes\":128,\"pmr_regions\":%u,\"all_regions_free\":true,\"page_bytes\":%lu,\"empty_clear_executed\":%s,\"engine_initialized\":false}\n",
                cycle, Count, system.dwPageSize, cycle == 1 ? "true" : "false");
  }
  rpmalloc_finalize();
  std::puts("{\"record_kind\":\"pear_guest_map_terminal\",\"cycles\":2,\"passed\":true}");
  return 0;
}
