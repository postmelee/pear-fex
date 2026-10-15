// SPDX-License-Identifier: MIT
// Original data-only observation of the selected FEX/libc++ PMR types.
#include <cstdint>
#include <FEXCore/fextl/memory.h>
#include "Interface/Core/LookupCache.h"
using Map = FEXCore::GuestToHostMap::BlockLinksMapType;
using Node = std::__tree_node<std::__value_type<Map::key_type, Map::mapped_type>, void*>;
using Resource = fextl::pmr::named_monotonic_page_buffer_resource;
using Allocator = std::pmr::polymorphic_allocator<std::byte>;
#ifdef PEAR_FEX_MEMORY_OWNER
#define PEAR_UNIT 13
#else
#define PEAR_UNIT 14
#endif
extern "C" {
__attribute__((used, section(".pearmet"))) extern const uint64_t pear_layout_pmr[] = {
 UINT64_C(0x504541524c415931), 1, PEAR_UNIT, 10,
 600, sizeof(Map), 601, alignof(Map),
 602, sizeof(Node), 603, alignof(Node),
 604, sizeof(Resource), 605, alignof(Resource),
 606, sizeof(Allocator), 607, alignof(Allocator),
 608, sizeof(Map::mapped_type), 609, FEXCore::Utils::FEX_PAGE_SIZE,
};
}
