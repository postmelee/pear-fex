// SPDX-License-Identifier: MIT
// Original finite ordinary-data storage; original heap provider is unchanged.
#include <FEXCore/Utils/AllocatorHooks.h>
#include <FEXCore/Utils/PearSourceGuard.h>
#include <atomic>
#include <cstddef>
#include <cstdint>
#ifdef PEAR_FEX_MEMORY_OWNER
#include <processthreadsapi.h>
#endif
namespace FEXCore::Allocator {
#ifdef PEAR_FEX_MEMORY_OWNER
namespace {
struct alignas(4096) PearEmptyObjectBacking {
  alignas(16) unsigned char Bytes[8192] {};
  // Start entries contain the run length; continuation entries use UINT16_MAX.
  uint16_t Runs[512] {};
};
constinit PearEmptyObjectBacking PearEmptyObjects {};
constinit std::atomic<uintptr_t> PearEmptyObjectThread {0};
// Reuse the selected Windows runtime's direct TEB thread-ID observation.
// The upstream custom CRT has no PE static-TLS directory; do not introduce
// a new static-TLS allocation just to identify this one owned thread.
uintptr_t PearObjectThread() { return static_cast<uintptr_t>(GetCurrentThreadId()); }
bool ReleasePearMetadataIfOwned(void* P) {
  const uintptr_t Start=reinterpret_cast<uintptr_t>(PearEmptyObjects.Bytes);
  const uintptr_t Address=reinterpret_cast<uintptr_t>(P);
  if (Address<Start || Address-Start>=sizeof(PearEmptyObjects.Bytes)) return false;
  PEAR_FEX_REQUIRE(PearEmptyObjectThread.load()==PearObjectThread(),"Finite object release thread");
  PEAR_FEX_REQUIRE((Address-Start)%16==0,"Finite object release alignment");
  const size_t Index=(Address-Start)/16;
  const size_t Count=PearEmptyObjects.Runs[Index];
  PEAR_FEX_REQUIRE(Count && Count<=512-Index,"Finite object release identity");
  for (size_t I=1;I<Count;++I)
    PEAR_FEX_REQUIRE(PearEmptyObjects.Runs[Index+I]==UINT16_MAX,"Finite object release extent");
  for (size_t I=0;I<Count;++I) PearEmptyObjects.Runs[Index+I]=0;
  return true;
}
}
bool InitializePearEmptyObjectStorage() {
  uintptr_t Expected=0;
  const auto Current=PearObjectThread();
  return Current && PearEmptyObjectThread.compare_exchange_strong(Expected,Current);
}
bool ShutdownPearEmptyObjectStorage() {
  const auto Current=PearObjectThread();
  if (!Current || PearEmptyObjectThread.load()!=Current) return false;
  for (const auto Run:PearEmptyObjects.Runs) if (Run) return false;
  PearEmptyObjectThread.store(0);return true;
}
void* AllocatePearMetadataStorage(size_t Alignment,size_t Size) {
  const uintptr_t Owner=PearEmptyObjectThread.load();
  if (!Owner) return aligned_alloc(Alignment,Size);
  if (Owner!=PearObjectThread() || !Size || Size>8192 || !Alignment ||
      Alignment>16 || (Alignment&(Alignment-1))) return nullptr;
  const size_t Count=(Size+15)/16;
  size_t Free=0;
  for (size_t I=0;I<512;++I) {
    Free=PearEmptyObjects.Runs[I] ? 0 : Free+1;
    if (Free!=Count) continue;
    const size_t Start=I+1-Count;
    PearEmptyObjects.Runs[Start]=static_cast<uint16_t>(Count);
    for (size_t J=1;J<Count;++J) PearEmptyObjects.Runs[Start+J]=UINT16_MAX;
    return PearEmptyObjects.Bytes+16*Start;
  }
  return nullptr;
}
#endif
void FreePearMetadataOrHeap(void* ptr) {
#ifdef PEAR_FEX_MEMORY_OWNER
  if (ReleasePearMetadataIfOwned(ptr)) return;
#endif
  return aligned_free(ptr);
}

}
