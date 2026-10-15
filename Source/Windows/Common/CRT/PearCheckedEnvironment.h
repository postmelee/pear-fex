// SPDX-License-Identifier: MIT
// Private checked reuse of the pinned CRT environment initializer. The original
// void initializer and its callback table are unchanged for existing modules.
#pragma once
#include <cstddef>
#include <cstdint>
namespace FEX::Windows::PearCRT {
enum class EnvironmentStatus : uint32_t { OK, Unavailable, Invalid, NativeFailure, ConversionFailure, AllocationFailure, CleanupFailure };
struct EnvironmentOutcome {
  EnvironmentStatus Status {EnvironmentStatus::Unavailable};
  int32_t NativeStatus {};
  bool ConversionSizeReturned {}, ConversionReturned {}, Published {};
  bool EnvAllocated {}, ArrayAllocated {}, EnvFreeAttempted {}, EnvFreeReturned {}, ArrayFreeAttempted {}, ArrayFreeReturned {};
  explicit operator bool() const { return Status==EnvironmentStatus::OK; }
};
bool IsOriginalEnvironmentInitializer(uintptr_t);
EnvironmentOutcome InitializeEnvironmentChecked(const wchar_t* ActualEnvironment,size_t ActualCharacters);
}
