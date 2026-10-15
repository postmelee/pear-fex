// SPDX-License-Identifier: MIT
// Private original finite observation record, not a stable runtime API.
#pragma once
#include <cstdint>
namespace FEX::Windows::PearEmptyInit {
enum class Phase : uint32_t { Proof, Image, TLS, Environment, UnixPID, Owner, HostBasics, CRTProcess, CRTThread, Context, Thread, Cleanup };
enum class Status : uint32_t { OK, Unavailable, Invalid, NativeFailure, RPMallocFailure, SourceFailure, OwnerFailure, AllocationFailure };
enum class Domain : uint32_t { None, NTStatus, RPMallocReturn, OwnerWire };
struct Outcome {
  Status State {Status::Unavailable};
  Phase At {Phase::Proof};
  Domain ErrorDomain {};
  int32_t ErrorCode {};
  uint32_t OwnerStatus {}, OwnerErrorDomain {};
  explicit operator bool() const { return State==Status::OK; }
};
struct Report {
  uint32_t Version {1}, Size {sizeof(Report)};
  Outcome Primary {}, Cleanup {}, ConstructionCleanup {}, FinalCleanup {};
  uint32_t ConstructionCleanupAttempted {}, FinalCleanupAttempted {};
  uint32_t CRTProcessAttempted {}, CRTProcessReturned {}, CRTThreadAttempted {}, CRTThreadReturned {};
  uint32_t CallbackAttempts {}, CallbackReturns {}, TLSCallbacks {}, TLSObserved {}, UnixPIDObserved {}, OwnerObserved {};
  uint32_t EnvironmentCheckedAttempted {}, EnvironmentCheckedReturned {}, EnvironmentPublished {};
  int32_t EnvironmentNativeStatus {};
  uint32_t EnvironmentStatus {}, EnvironmentEnvAllocated {}, EnvironmentArrayAllocated {};
  uint32_t EnvironmentEnvFreeAttempted {}, EnvironmentEnvFreeReturned {}, EnvironmentArrayFreeAttempted {}, EnvironmentArrayFreeReturned {};
  uint32_t ContextAttempted {}, ContextCreated {}, CoreAttempted {}, CoreCreated {}, ThreadAttempted {}, ThreadCreated {};
  uint32_t ThreadDestroyed {}, ThreadAllocatorCompleted {}, ContextDestroyed {}, ContextAllocatorCompleted {};
  uint32_t ThreadCRTFinalized {}, ConfigShutdown {}, OutputOnly {}, OneShotRefused {};
  uint32_t GuestExecution {}, DeliveredHandlers {}, ARM64ECExecution {}, Stage3Complete {};
};
} // namespace FEX::Windows::PearEmptyInit
