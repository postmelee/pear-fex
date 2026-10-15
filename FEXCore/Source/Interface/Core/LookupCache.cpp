// SPDX-License-Identifier: MIT
/*
$info$
tags: glue|block-database
desc: Stores information about blocks, and provides C++ implementations to lookup the blocks
$end_info$
*/

#include <FEXCore/Utils/PearSourceGuard.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/HLE/SyscallHandler.h>

#include "Interface/Context/Context.h"
#include "Interface/Core/LookupCache.h"
#ifdef PEAR_FEX_MEMORY_OWNER
#include <FEXCore/Utils/PearDataMemory.h>
#endif

namespace FEXCore {
GuestToHostMap::GuestToHostMap()
  : BlockLinks_mbr {"FEXMem_BlockLinks"} {
#ifndef PEAR_FEX_MEMORY_OWNER
  BlockLinks_pma = fextl::make_unique<std::pmr::polymorphic_allocator<std::byte>>(&BlockLinks_mbr);
  // Setup our PMR map.
  BlockLinks = BlockLinks_pma->new_object<BlockLinksMapType>();
#endif
}

GuestToHostMap::~GuestToHostMap() {
  // The inline owner map is destroyed before its resource by member order.
#ifndef PEAR_FEX_MEMORY_OWNER
  BlockLinks_pma->delete_object(BlockLinks);
#endif
}

LookupCache::LookupCache(FEXCore::Context::ContextImpl* CTX)
  : ctx {CTX} {

  TotalCacheSize = ctx->Config.VirtualMemSize / FEXCore::Utils::FEX_PAGE_SIZE * 8 + CODE_SIZE + MAX_L1_SIZE;

  // Block cache ends up looking like this
  // PageMemoryMap[VirtualMemoryRegion >> 12]
  //       |
  //       v
  // PageMemory[Memory & (VIRTUAL_PAGE_SIZE - 1)]
  //       |
  //       v
  // Pointer to Code
  //
  // Allocate a region of memory that we can use to back our block pointers
  // We need one pointer per page of virtual memory
  // At 64GB of virtual memory this will allocate 128MB of virtual memory space
#ifdef PEAR_FEX_MEMORY_OWNER
  void* Backing=nullptr;
  PearCreation=FEXCore::Allocator::ReservePearData(TotalCacheSize,false,Backing);
  if (!PearCreation) return;
  PagePointer=reinterpret_cast<uintptr_t>(Backing);
#else
  PagePointer = reinterpret_cast<uintptr_t>(FEXCore::Allocator::VirtualAlloc(TotalCacheSize, false, false));
  PEAR_FEX_REQUIRE(PagePointer != -1ULL, "Failed to allocate PagePointer");
#endif

  // Disable THP on the Lookup cache.
  FEXCore::Allocator::VirtualTHPControl(reinterpret_cast<const void*>(PagePointer), TotalCacheSize, FEXCore::Allocator::THPControl::Disable);

  FEXCore::Allocator::VirtualName("FEXMem_Lookup", reinterpret_cast<void*>(PagePointer),
                                  ctx->Config.VirtualMemSize / FEXCore::Utils::FEX_PAGE_SIZE * 8 + CODE_SIZE);
  CTX->SyscallHandler->MarkOvercommitRange(PagePointer, TotalCacheSize);

  // Allocate our memory backing our pages
  // We need 32KB per guest page (One pointer per byte)
  // XXX: We can drop down to 16KB if we store 4byte offsets from the code base
  // We currently limit to 128MB of real memory for caching for the total cache size.
  // Can end up being inefficient if we compile a small number of blocks per page
  PageMemory = PagePointer + ctx->Config.VirtualMemSize / FEXCore::Utils::FEX_PAGE_SIZE * 8;

  // L1 Cache
  L1Pointer = PageMemory + CODE_SIZE;
  FEXCore::Allocator::VirtualName("FEXMem_Lookup_L1", reinterpret_cast<void*>(L1Pointer), MAX_L1_SIZE);

  VirtualMemSize = ctx->Config.VirtualMemSize;

  if (DynamicL1Cache()) {
    // Start at minimum size when dynamic.
    L1PointerMask = MIN_L1_ENTRIES - 1;
  } else {
    // Start at maximum instead.
    L1PointerMask = MAX_L1_ENTRIES - 1;
  }
}

#ifdef PEAR_FEX_MEMORY_OWNER
fextl::unique_ptr<LookupCache> LookupCache::CreatePear(FEXCore::Context::ContextImpl* CTX,FEXCore::Utils::PearFEXMemory::Result& Outcome) {
  auto Actual=FEXCore::Allocator::TryMakePearMetadataObject<LookupCache>(CTX);
  if (!Actual) { Outcome={PEAR_FEX_UNAVAILABLE,0,0}; return {}; }
  Outcome=Actual->PearCreation;
  return Outcome ? std::move(Actual) : fextl::unique_ptr<LookupCache> {};
}
FEXCore::Utils::PearFEXMemory::Result LookupCache::ReleasePearBacking() {
  if (!PagePointer) return {PEAR_FEX_OK,0,0};
  const auto Result=FEXCore::Allocator::ReleasePearData(reinterpret_cast<void*>(PagePointer));
  if (!Result) return Result; // Keep the exact still-owned pointer for quarantine.
  ctx->SyscallHandler->UnmarkOvercommitRange(PagePointer,TotalCacheSize);
  PagePointer=0;
  return Result;
}
#endif
LookupCache::~LookupCache() {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Native cleanup owns release. A failed constructor never published backing.
  PEAR_FEX_REQUIRE(!PagePointer,"Lookup backing must be released before destruction");
#else
  FEXCore::Allocator::VirtualFree(reinterpret_cast<void*>(PagePointer), TotalCacheSize);
  ctx->SyscallHandler->UnmarkOvercommitRange(PagePointer, TotalCacheSize);
#endif

  // No need to free BlockLinks map.
  // These will get freed when their memory allocators are deallocated.
}

void LookupCache::ClearL2Cache(const FEXCore::LookupCacheBaseLockToken& lk) {
  // Clear out the page memory
  // PagePointer and PageMemory are sequential with each other. Clear both at once.
  FEXCore::Allocator::VirtualDontNeed(reinterpret_cast<void*>(PagePointer),
                                      ctx->Config.VirtualMemSize / FEXCore::Utils::FEX_PAGE_SIZE * 8 + CODE_SIZE, false);
  AllocateOffset = 0;
}

void LookupCache::ClearThreadLocalCaches(const LookupCacheWriteLockToken&) {
  // TODO: Preserve code cache entries?
  // Clear L1 and L2 by clearing the full cache.
  FEXCore::Allocator::VirtualDontNeed(reinterpret_cast<void*>(PagePointer), TotalCacheSize, false);

  // TODO: Rename this member to avoid confusion with code caching
  CachedCodePages.clear();
}

void LookupCache::ClearCache(const LookupCacheWriteLockToken& lk) {
  // Clear L1 and L2 by clearing the full cache.
  ClearThreadLocalCaches(lk);
  Shared->ClearCache(lk);
}

void GuestToHostMap::ClearCache(const LookupCacheWriteLockToken&) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Preserve every real source link before replacing its map. The native
  // invalidation batch drains these tickets only after all locks are released.
  for (const auto& Item:*BlockLinks) {
    const auto Queued=FEXCore::CPU::PearJITLinks::Queue(Item.second);
    PEAR_FEX_REQUIRE_RESULT(!!Queued, "Pear cache-clear link queue refused: status {}, domain {}, code {}", Queued);
  }
#endif
  // Link tickets above are values copied before their map storage is retired.
#ifdef PEAR_FEX_MEMORY_OWNER
  std::destroy_at(BlockLinks);
  BlockLinks_mbr.release();
  std::construct_at(BlockLinks,&BlockLinks_mbr);
#else
  BlockLinks_pma->delete_object(BlockLinks);
  BlockLinks_mbr.release();
  BlockLinks = BlockLinks_pma->new_object<BlockLinksMapType>();
#endif
  // All code is gone, clear the block list
  BlockList.clear();
}

} // namespace FEXCore
