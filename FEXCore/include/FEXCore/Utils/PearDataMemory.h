// SPDX-License-Identifier: MIT
// Checked ordinary data memory; never executable memory or an owner-wire extension.
#pragma once
#include <FEXCore/Utils/PearFEXMemory.h>
#include <FEXCore/fextl/memory.h>
namespace FEXCore::Allocator {
FEXCore::Utils::PearFEXMemory::Result ReservePearData(size_t Size, bool Commit, void*& Address);
FEXCore::Utils::PearFEXMemory::Result ReleasePearData(void* Address);
// Finite empty-init backing for objects enlarged by ownership metadata.
// The ordinary loaded profile keeps the existing allocator when this is inactive.
bool InitializePearEmptyObjectStorage();
bool ShutdownPearEmptyObjectStorage();
void* AllocatePearMetadataStorage(size_t Alignment,size_t Size);
template<class T, class... Args>
fextl::unique_ptr<T> TryMakePearMetadataObject(Args&&... Arguments) {
  void* Storage=AllocatePearMetadataStorage(alignof(T),sizeof(T));
  if (!Storage) return {};
  return fextl::unique_ptr<T> {::new (Storage) T(std::forward<Args>(Arguments)...)};
}
// A checked outer allocation does not qualify allocations inside T's constructor.
template<class T, class... Args>
fextl::unique_ptr<T> TryMakePearObject(Args&&... Arguments) {
  void* Storage=aligned_alloc(alignof(T),sizeof(T));
  if (!Storage) return {};
  return fextl::unique_ptr<T> {::new (Storage) T(std::forward<Args>(Arguments)...)};
}
} // namespace FEXCore::Allocator
