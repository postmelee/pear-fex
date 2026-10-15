// SPDX-License-Identifier: MIT
// Conservative Pear downstream policy; no engine or privileged API is invoked.
#pragma once
#include <string_view>

namespace FEX::Windows::DarwinPolicy {
struct Setting { std::string_view JSONName; std::string_view EnvironmentName; std::string_view Value; };
inline constexpr Setting Settings[] {
  {"DiskCache", "FEX_DISKCACHE", "0"},
  {"ProfileStats", "FEX_PROFILESTATS", "0"},
  // The Darwin owner does not admit mapped persistent or AOT code.
  {"EnableCodeCachingWIP", "FEX_ENABLECODECACHINGWIP", "0"},
  {"EnableLazyCodeCachingWIP", "FEX_ENABLELAZYCODECACHINGWIP", "0"},
  {"EnableCodeCacheValidation", "FEX_ENABLECODECACHEVALIDATION", "0"},
  {"TSOEnabled", "FEX_TSOENABLED", "1"},
  {"VectorTSOEnabled", "FEX_VECTORTSOENABLED", "1"},
  {"MemcpySetTSOEnabled", "FEX_MEMCPYSETTSOENABLED", "1"},
  // Retain the upstream half-barrier handler; runtime suitability is unperformed.
  {"HalfBarrierTSOEnabled", "FEX_HALFBARRIERTSOENABLED", "1"},
  {"StrictInProcessSplitLocks", "FEX_STRICTINPROCESSSPLITLOCKS", "1"},
  {"KernelUnalignedAtomicBackpatching", "FEX_KERNELUNALIGNEDATOMICBACKPATCHING", "0"},
  {"HostFeatures", "FEX_HOSTFEATURES", "0"},
};
constexpr bool AcceptJSON(std::string_view name, std::string_view value) {
  for (const auto& setting : Settings) if (setting.JSONName == name) return value == setting.Value;
  // Additional application tuning needs a reviewed platform-specific contract.
  return false;
}
constexpr bool AcceptEnvironment(std::string_view name, std::string_view value) {
  for (const auto& setting : Settings) if (setting.EnvironmentName == name) return value == setting.Value;
  // These upstream selectors name configuration locations; loaded entries are
  // independently checked before each Set, including per-application layers.
  return name == "FEX_APP_CONFIG" || name == "FEX_APP_DATA_LOCATION" ||
         name == "FEX_APP_CONFIG_LOCATION" || name == "FEX_APP_CACHE_LOCATION";
}
[[nodiscard]] bool Apply();
} // namespace FEX::Windows::DarwinPolicy
