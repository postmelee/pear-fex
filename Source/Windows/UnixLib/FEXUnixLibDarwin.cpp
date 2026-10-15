// SPDX-License-Identifier: MIT
// Pear Darwin implementation of the pinned FEX eight-call UnixLib ABI.
// Upstream FEX notices remain applicable; this file is not an upstream submission.
#include "FEXUnixLib.h"
#include <cerrno>
#include <cstdint>
#include <limits>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

using NTSTATUS = int32_t;
using unixlib_entry_t = NTSTATUS (*)(void*);
constexpr NTSTATUS STATUS_SUCCESS = 0;
constexpr NTSTATUS STATUS_INVALID_PARAMETER = static_cast<int32_t>(0xC000000D);
constexpr NTSTATUS STATUS_INVALID_HANDLE = static_cast<int32_t>(0xC0000008);
constexpr NTSTATUS STATUS_NOT_SUPPORTED = static_cast<int32_t>(0xC00000BB);
constexpr NTSTATUS STATUS_INTERNAL_ERROR = static_cast<int32_t>(0xC00000E5);
static_assert(sizeof(void*) == 8 && sizeof(NTSTATUS) == 4);

static bool ValidRange(const void* address, size_t size) {
  auto start = reinterpret_cast<uintptr_t>(address);
  return address && size && size <= std::numeric_limits<uintptr_t>::max() - start;
}

static NTSTATUS FEXUnixLib_SetHardwareTSOControlHandler(void* data) {
  if (!data) return STATUS_INVALID_PARAMETER;
  // No per-thread request is attempted. Callers must retain software ordering.
  return STATUS_NOT_SUPPORTED;
}

static NTSTATUS FEXUnixLib_SetKernelUnalignedAtomicControlHandler(void* data) {
  if (!data) return STATUS_INVALID_PARAMETER;
  auto args = static_cast<const FEXUnixLib_SetKernelUnalignedAtomicControl*>(data);
  constexpr uint64_t known = FEX_UNALIGN_ATOMIC_EMULATE | FEX_UNALIGN_ATOMIC_BACKPATCH | FEX_UNALIGN_ATOMIC_STRICT_SPLIT_LOCKS;
  return args->Flags & ~known ? STATUS_INVALID_PARAMETER : STATUS_NOT_SUPPORTED;
}

static NTSTATUS FEXUnixLib_MadviseHandler(void* data) {
  if (!data) return STATUS_INVALID_PARAMETER;
  auto args = static_cast<const FEXUnixLib_Madvise*>(data);
  if (!ValidRange(args->Addr, args->Size)) return STATUS_INVALID_PARAMETER;
  // The source caller sends Linux MADV_HUGEPAGE=14/MADV_NOHUGEPAGE=15.
  // Neither integer is forwarded to Darwin's different advice namespace.
  return args->Advise == 14 || args->Advise == 15 ? STATUS_NOT_SUPPORTED : STATUS_INVALID_PARAMETER;
}

static NTSTATUS FEXUnixLib_SetVMANameHandler(void* data) {
  if (!data) return STATUS_INVALID_PARAMETER;
  auto args = static_cast<const FEXUnixLib_SetVMAName*>(data);
  if (!ValidRange(args->Addr, args->Size) || !args->Name) return STATUS_INVALID_PARAMETER;
  return STATUS_NOT_SUPPORTED;
}

static NTSTATUS FEXUnixLib_GetSHMStatsVMAHandler(void* data) {
  if (!data) return STATUS_INVALID_PARAMETER;
  auto args = static_cast<FEXUnixLib_GetSHMStatsVMA*>(data);
  args->SHMBase = nullptr;
  // Profiling stays disabled; no stats file or memory is created.
  return STATUS_NOT_SUPPORTED;
}

static NTSTATUS FEXUnixLib_DeleteSHMStatsFileHandler(void*) {
  // Unsupported also when no stats file exists; absence is not fake success.
  return STATUS_NOT_SUPPORTED;
}

static NTSTATUS FEXUnixLib_MapFileHandler(void* data) {
  if (!data) return STATUS_INVALID_PARAMETER;
  auto args = static_cast<FEXUnixLib_MapFile*>(data);
  args->Result = nullptr;
  int fd = args->FD;
  args->FD = -1;
  if (fd < 0) { errno = EBADF; return STATUS_INVALID_HANDLE; }
  auto fail = [fd](NTSTATUS status, int reason) {
    // The Wine handle translation transfers one duplicate; close exactly once.
    close(fd);
    errno = reason;
    return status;
  };
  if (!args->MapSize || args->MapSize > std::numeric_limits<size_t>::max())
    return fail(STATUS_INVALID_PARAMETER, EINVAL);
  struct stat info {};
  if (fstat(fd, &info)) return fail(STATUS_INVALID_HANDLE, errno);
  if (!S_ISREG(info.st_mode)) return fail(STATUS_NOT_SUPPORTED, ENOTSUP);
  if (info.st_size < 0 || args->MapSize > static_cast<uint64_t>(info.st_size))
    return fail(STATUS_INVALID_PARAMETER, EINVAL);
  void* mapped = mmap(nullptr, static_cast<size_t>(args->MapSize), PROT_READ, MAP_SHARED, fd, 0);
  int map_error = errno;
  int closed = close(fd);
  int close_error = errno;
  if (mapped == MAP_FAILED) { errno = map_error; return STATUS_INTERNAL_ERROR; }
  if (closed) {
    munmap(mapped, static_cast<size_t>(args->MapSize));
    errno = close_error;
    return STATUS_INTERNAL_ERROR;
  }
  args->Result = mapped;
  return STATUS_SUCCESS;
}

static NTSTATUS FEXUnixLib_GetPIDHandler(void* data) {
  if (!data) return STATUS_INVALID_PARAMETER;
  auto args = static_cast<FEXUnixLib_GetPID*>(data);
  args->Result = 0;
  auto pid = getpid();
  if (pid <= 0) return STATUS_INTERNAL_ERROR;
  args->Result = static_cast<uint32_t>(pid);
  return STATUS_SUCCESS;
}

extern "C" const unixlib_entry_t __wine_unix_call_funcs[] = {
  FEXUnixLib_SetHardwareTSOControlHandler,
  FEXUnixLib_SetKernelUnalignedAtomicControlHandler,
  FEXUnixLib_MadviseHandler,
  FEXUnixLib_SetVMANameHandler,
  FEXUnixLib_GetSHMStatsVMAHandler,
  FEXUnixLib_DeleteSHMStatsFileHandler,
  FEXUnixLib_MapFileHandler,
  FEXUnixLib_GetPIDHandler,
};
extern "C" const uint32_t pear_fex_unix_call_count = static_cast<uint32_t>(FEXUnixLibFunctions::MAX);
static_assert(sizeof(__wine_unix_call_funcs) / sizeof(__wine_unix_call_funcs[0]) == static_cast<uint32_t>(FEXUnixLibFunctions::MAX));
