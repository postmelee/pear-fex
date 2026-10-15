// SPDX-License-Identifier: MIT
// Original bounded-storage controls; actual source bodies, no FEX initialization.
#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <thread>
static size_t HeapAllocations,HeapFrees;
// Substitute only the Windows thread-ID provider in this native Mac control.
static uint32_t GetCurrentThreadId() {
  static std::atomic<uint32_t> Next {1};
  thread_local const uint32_t ID=Next.fetch_add(1);
  return ID;
}
void rpfree(void* P) { ++HeapFrees;std::free(P); }
#define PEAR_FEX_MEMORY_OWNER 1
#define PEAR_FEX_REQUIRE(C,...) assert(C)
namespace FEXCore::Allocator {
void* aligned_alloc(size_t A,size_t N) { ++HeapAllocations;return std::aligned_alloc(A,((N+A-1)/A)*A); }
void aligned_free(void* P) { ::rpfree(P); }
#include "empty_object_storage_under_test.inc"
}
int main() {
 using namespace FEXCore::Allocator;
 static_assert(sizeof(PearEmptyObjectBacking)==12288);
 void* Ordinary=AllocatePearMetadataStorage(16,256);assert(Ordinary && HeapAllocations==1);
 FreePearMetadataOrHeap(Ordinary);assert(HeapFrees==1);
 assert(InitializePearEmptyObjectStorage());assert(!InitializePearEmptyObjectStorage());
 const size_t Sizes[]={1904,736,816,256,160,216,128};void* Objects[7] {};
 for (size_t I=0;I<7;++I) { Objects[I]=AllocatePearMetadataStorage(16,Sizes[I]);assert(Objects[I]); }
 assert(HeapAllocations==1 && HeapFrees==1 && !ShutdownPearEmptyObjectStorage());
 for (size_t I:{size_t{3},size_t{0},size_t{6},size_t{2},size_t{5},size_t{1},size_t{4}}) FreePearMetadataOrHeap(Objects[I]);
 void* Whole=AllocatePearMetadataStorage(16,8192);assert(Whole);
 assert(!AllocatePearMetadataStorage(16,1));assert(!ShutdownPearEmptyObjectStorage());
 FreePearMetadataOrHeap(Whole);
 for (size_t A:{size_t{0},size_t{3},size_t{32}}) assert(!AllocatePearMetadataStorage(A,16));
 assert(!AllocatePearMetadataStorage(16,0) && !AllocatePearMetadataStorage(16,8193));
 bool ForeignAllocationRefused=false,ForeignShutdownRefused=false;
 std::thread Other([&]{ForeignAllocationRefused=!AllocatePearMetadataStorage(16,16);ForeignShutdownRefused=!ShutdownPearEmptyObjectStorage();});Other.join();
 assert(ForeignAllocationRefused && ForeignShutdownRefused);
 assert(ShutdownPearEmptyObjectStorage());assert(!ShutdownPearEmptyObjectStorage());
 assert(InitializePearEmptyObjectStorage());void* Again=AllocatePearMetadataStorage(16,8192);assert(Again==Whole);FreePearMetadataOrHeap(Again);assert(ShutdownPearEmptyObjectStorage());
 assert(HeapAllocations==1 && HeapFrees==1);
 puts("{\"passed\":true,\"backing_bytes\":12288,\"engine_initialized\":false}");
}
