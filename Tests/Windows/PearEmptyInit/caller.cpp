// SPDX-License-Identifier: MIT
// Original ordinary ARM64 PE caller. It has no proof/permission/runtime flags.
#include "Source/Windows/PearEmptyInit/Report.h"
#include <windows.h>
#include <cstdio>
int main() {
  using FEX::Windows::PearEmptyInit::Report;
  auto Module=LoadLibraryW(L"libpearemptyinit.dll");
  if (!Module) { std::printf("pear_fex_empty caller load failed code=%lu\n",GetLastError());return 1; }
  using Call=uint32_t(WINAPI*)(Report*);
  const auto Function=reinterpret_cast<Call>(GetProcAddress(Module,"PearEmptySourceInit"));
  if (!Function) { std::printf("pear_fex_empty caller export failed code=%lu\n",GetLastError());return 1; }
  Report Actual;const auto Returned=Function(&Actual);
  std::printf("pear_fex_empty result=%u primary=%u phase=%u domain=%u code=%d owner_status=%u owner_domain=%u cleanup=%u cleanup_phase=%u cleanup_domain=%u cleanup_code=%d cleanup_owner_status=%u cleanup_owner_domain=%u construction_cleanup_attempt=%u construction_cleanup=%u construction_cleanup_phase=%u construction_cleanup_domain=%u construction_cleanup_code=%d construction_cleanup_owner_status=%u construction_cleanup_owner_domain=%u final_cleanup_attempt=%u final_cleanup=%u final_cleanup_phase=%u final_cleanup_domain=%u final_cleanup_code=%d final_cleanup_owner_status=%u final_cleanup_owner_domain=%u process_attempt=%u process_return=%u thread_attempt=%u thread_return=%u callbacks_attempt=%u callbacks_return=%u context_created=%u core_created=%u thread_created=%u thread_destroyed=%u thread_allocator=%u context_destroyed=%u context_allocator=%u thread_finalize=%u config_shutdown=%u guest=%u delivered=%u ec=%u stage3=%u\n",
    Returned,uint32_t(Actual.Primary.State),uint32_t(Actual.Primary.At),uint32_t(Actual.Primary.ErrorDomain),Actual.Primary.ErrorCode,
    Actual.Primary.OwnerStatus,Actual.Primary.OwnerErrorDomain,uint32_t(Actual.Cleanup.State),uint32_t(Actual.Cleanup.At),
    uint32_t(Actual.Cleanup.ErrorDomain),Actual.Cleanup.ErrorCode,Actual.Cleanup.OwnerStatus,Actual.Cleanup.OwnerErrorDomain,
    Actual.ConstructionCleanupAttempted,uint32_t(Actual.ConstructionCleanup.State),uint32_t(Actual.ConstructionCleanup.At),
    uint32_t(Actual.ConstructionCleanup.ErrorDomain),Actual.ConstructionCleanup.ErrorCode,
    Actual.ConstructionCleanup.OwnerStatus,Actual.ConstructionCleanup.OwnerErrorDomain,
    Actual.FinalCleanupAttempted,uint32_t(Actual.FinalCleanup.State),uint32_t(Actual.FinalCleanup.At),
    uint32_t(Actual.FinalCleanup.ErrorDomain),Actual.FinalCleanup.ErrorCode,
    Actual.FinalCleanup.OwnerStatus,Actual.FinalCleanup.OwnerErrorDomain,Actual.CRTProcessAttempted,Actual.CRTProcessReturned,
    Actual.CRTThreadAttempted,Actual.CRTThreadReturned,Actual.CallbackAttempts,Actual.CallbackReturns,
    Actual.ContextCreated,Actual.CoreCreated,Actual.ThreadCreated,Actual.ThreadDestroyed,Actual.ThreadAllocatorCompleted,
    Actual.ContextDestroyed,Actual.ContextAllocatorCompleted,Actual.ThreadCRTFinalized,Actual.ConfigShutdown,
    Actual.GuestExecution,Actual.DeliveredHandlers,Actual.ARM64ECExecution,Actual.Stage3Complete);
  // A refused actual object remains alive with its dependencies until owned
  // process cleanup. Do not unload a DLL containing unresolved source state.
  return Returned==0 && Actual.FinalCleanupAttempted==1 && Actual.Cleanup.State==FEX::Windows::PearEmptyInit::Status::OK ? 0 : 1;
}
