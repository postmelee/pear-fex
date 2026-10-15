// SPDX-License-Identifier: MIT
// Original Pear downstream guard for the selected source owner profile.
// Preserve upstream LOGMAN asserts and no-exception/fatal policy; this helper
// changes no global logging macro, build type, permission or execution grant.
#pragma once
#include <FEXCore/Utils/LogManager.h>
#include <cstdint>
#ifdef PEAR_FEX_MEMORY_OWNER
namespace FEXCore::Utils::PearSourceGuard {
[[noreturn]] inline void Fail(const char* File,unsigned Line,const char* Function) {
  // Genuine MFmt is unconditionally noreturn and ends in ForcedAssert even
  // when ASSERTIONS_ENABLED==0. Only constant source-site facts are formatted:
  // do not dereference rejected caller fields while constructing diagnostics.
  LogMan::Throw::MFmt("{}:{} {}: Pear source guard refused",fmt::make_format_args(File,Line,Function));
}
[[noreturn]] inline void FailResult(const char* File,unsigned Line,const char* Function,
                                  uint32_t Status,uint32_t Domain,int32_t Code) {
  // These values are copies of an actual local Result, never refused source
  // Frame/Thread fields. Preserve the original numeric failure provenance.
  LogMan::Throw::MFmt("{}:{} {}: Pear source guard refused: status {}, domain {}, code {}",
                     fmt::make_format_args(File,Line,Function,Status,Domain,Code));
}
} // namespace FEXCore::Utils::PearSourceGuard
#define PEAR_FEX_REQUIRE(pred, message, ...) \
  do { \
    const bool PearGuardPassed=!!(pred); \
    if (!PearGuardPassed) ::FEXCore::Utils::PearSourceGuard::Fail(__FILE_NAME__,__LINE__,__FUNCTION__); \
  } while (0)
#define PEAR_FEX_REQUIRE_RESULT(pred, message, result) \
  do { \
    const bool PearGuardPassed=!!(pred); \
    if (!PearGuardPassed) { \
      const auto& PearGuardResult=(result); \
      ::FEXCore::Utils::PearSourceGuard::FailResult(__FILE_NAME__,__LINE__,__FUNCTION__, \
        PearGuardResult.Status,PearGuardResult.ErrorDomain,PearGuardResult.ErrorCode); \
    } \
  } while (0)
#else
// Non-owner upstream branches retain their exact original assertion behavior.
#define PEAR_FEX_REQUIRE(pred, message, ...) LOGMAN_THROW_A_FMT(pred,message __VA_OPT__(,) __VA_ARGS__)
#define PEAR_FEX_REQUIRE_RESULT(pred, message, result) \
  LOGMAN_THROW_A_FMT(pred,message,(result).Status,(result).ErrorDomain,(result).ErrorCode)
#endif
