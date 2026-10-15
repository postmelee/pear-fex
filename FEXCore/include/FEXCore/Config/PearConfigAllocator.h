// SPDX-License-Identifier: MIT
// Original finite config backing; normal layers retain the FEX allocator.
#pragma once
#include <FEXCore/fextl/allocator.h>
#include <FEXCore/Utils/PearSourceGuard.h>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace FEXCore::Config::Pear {
struct Arena {
  // One bucket allocation (at most 32 pointers) plus fourteen nodes no larger
  // than 128 bytes, each aligned at most 16. No configured string exceeds SSO.
  static constexpr size_t MAX_ENTRIES=14;
  static constexpr size_t CAPACITY=4096;
  alignas(16) std::byte Bytes[CAPACITY] {};
  size_t Used {}, Requests {}, Live {};
  bool Sealed {};
  static_assert(32*sizeof(void*)+MAX_ENTRIES*(128+15)<=CAPACITY);
  bool CanAllocate(size_t Size,size_t Alignment) const {
    if (Sealed || !Size || !Alignment || (Alignment&(Alignment-1)) || Alignment>16 || Requests>=MAX_ENTRIES+1)
      return false;
    const size_t Aligned=(Used+Alignment-1)&~(Alignment-1);
    return Aligned<=CAPACITY && Size<=CAPACITY-Aligned;
  }
  void* Allocate(size_t Size,size_t Alignment) {
    PEAR_FEX_REQUIRE(CanAllocate(Size,Alignment),"Unsupported finite config allocation pattern");
    Used=(Used+Alignment-1)&~(Alignment-1);
    auto* Result=Bytes+Used;Used+=Size;++Requests;++Live;return Result;
  }
  void Release(void* Pointer,size_t Size) {
    const auto Start=reinterpret_cast<uintptr_t>(Bytes);
    const auto Address=reinterpret_cast<uintptr_t>(Pointer);
    PEAR_FEX_REQUIRE(Live && Address>=Start && Address-Start<=Used && Size<=Used-(Address-Start),
                     "Foreign finite config release");
    --Live;
  }
};
template<typename T> struct Allocator {
  using value_type=T;
  using is_always_equal=std::false_type;
  Arena* Storage {};
  Allocator()=default;
  explicit Allocator(Arena* Value):Storage {Value} {}
  template<typename U> Allocator(const Allocator<U>& Other):Storage {Other.Storage} {}
  T* allocate(size_t Count) {
    if (!Storage) return fextl::FEXAlloc<T> {}.allocate(Count);
    // These are pinned-container contracts, not recoverable OOM paths. All
    // backing is already present before the real standard container is called.
    PEAR_FEX_REQUIRE(sizeof(T)<=128 && alignof(T)<=16 && Count && Count<=32 &&
                     Count<=std::numeric_limits<size_t>::max()/sizeof(T),"Unsupported finite config rebound type");
    return static_cast<T*>(Storage->Allocate(Count*sizeof(T),alignof(T)));
  }
  void deallocate(T* Pointer,size_t Count) noexcept {
    if (!Storage) { fextl::FEXAlloc<T> {}.deallocate(Pointer,Count);return; }
    PEAR_FEX_REQUIRE(Count<=std::numeric_limits<size_t>::max()/sizeof(T),"Invalid finite config release size");
    Storage->Release(Pointer,Count*sizeof(T));
  }
  template<typename U> bool operator==(const Allocator<U>& Other) const noexcept {return Storage==Other.Storage;}
};
} // namespace FEXCore::Config::Pear
