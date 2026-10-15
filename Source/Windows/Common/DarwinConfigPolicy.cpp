// SPDX-License-Identifier: MIT
#include "DarwinConfigPolicy.h"
#include <FEXCore/Config/Config.h>

namespace FEX::Windows::DarwinPolicy {
bool Apply() {
#ifdef PEAR_FEX_DARWIN
  // Inspect loaded requests before mutation. Typed bool getters can silently
  // substitute defaults for malformed strings; raw Get keeps that refusal real.
  constexpr FEXCore::Config::ConfigOption CacheOptions[] {
    FEXCore::Config::CONFIG_DISKCACHE,
    FEXCore::Config::CONFIG_PROFILESTATS,
    FEXCore::Config::CONFIG_ENABLECODECACHINGWIP,
    FEXCore::Config::CONFIG_ENABLELAZYCODECACHINGWIP,
    FEXCore::Config::CONFIG_ENABLECODECACHEVALIDATION,
  };
  for (const auto Option : CacheOptions) {
    const auto Loaded = FEXCore::Config::Get(Option);
    // Absent uses the pinned false default; explicit requests must be canonical
    // zero/false. A true or malformed loaded request is never overwritten.
    if (Loaded && **Loaded != "0" && **Loaded != "false") return false;
  }
  // Apply after ReloadMetaLayer and before profiler/context/engine creation.
  FEXCore::Config::Set(FEXCore::Config::CONFIG_DISKCACHE, "0");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_PROFILESTATS, "0");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_ENABLECODECACHINGWIP, "0");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_ENABLELAZYCODECACHINGWIP, "0");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_ENABLECODECACHEVALIDATION, "0");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_TSOENABLED, "1");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_VECTORTSOENABLED, "1");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_MEMCPYSETTSOENABLED, "1");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_HALFBARRIERTSOENABLED, "1");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_STRICTINPROCESSSPLITLOCKS, "1");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_KERNELUNALIGNEDATOMICBACKPATCHING, "0");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_HOSTFEATURES, "0");
#endif
  return true;
}
} // namespace FEX::Windows::DarwinPolicy
