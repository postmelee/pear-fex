// SPDX-License-Identifier: MIT
// This isolated diagnostic unit requires SEH and asynchronous exception support.
// The rest of FEX retains its original no-exceptions compilation policy.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstddef>
#include <cstdint>
extern "C" __declspec(noinline) bool PearPhaseCopy(void* To, uint64_t From, size_t Size) {
  if (!To || !From || Size>96 || From>UINT64_MAX-Size) return false;
  __try {
    const volatile unsigned char* Source=reinterpret_cast<const volatile unsigned char*>(From);
    auto* Target=static_cast<unsigned char*>(To);
    for (size_t i=0;i<Size;++i) Target[i]=Source[i];
  } __except(GetExceptionCode()==EXCEPTION_ACCESS_VIOLATION || GetExceptionCode()==EXCEPTION_IN_PAGE_ERROR ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
    return false;
  }
  return true;
}
