// SPDX-License-Identifier: MIT
#include "DummyHandlers.h"
#ifdef PEAR_FEX_MEMORY_OWNER
#include <FEXCore/Utils/PearFEXRetirement.h>
#endif

namespace FEX::DummyHandlers {
thread_local FEXCore::Core::InternalThreadState* TLSThread;

void DummySignalDelegator::RegisterTLSState(FEXCore::Core::InternalThreadState* Thread) {
  TLSThread = Thread;
}

void DummySignalDelegator::UninstallTLSState(FEXCore::Core::InternalThreadState* Thread) {
  TLSThread = nullptr;
}

FEXCore::Core::InternalThreadState* DummySignalDelegator::GetTLSThread() {
  return TLSThread;
}

fextl::unique_ptr<FEXCore::HLE::SyscallHandler> CreateSyscallHandler() {
  return fextl::make_unique<DummySyscallHandler>();
}

fextl::unique_ptr<FEX::DummyHandlers::DummySignalDelegator> CreateSignalDelegator() {
  return fextl::make_unique<DummySignalDelegator>();
}

#ifdef PEAR_FEX_MEMORY_OWNER
// Narrow checked counterparts for the finite selected source target. The old
// factory bodies and the pinned fixed-field dependency constructors remain.
fextl::unique_ptr<FEXCore::HLE::SyscallHandler> CreatePearSyscallHandler(FEXCore::Utils::PearFEXMemory::Result& Outcome) {
  auto* Storage=FEXCore::Allocator::aligned_alloc(alignof(DummySyscallHandler),sizeof(DummySyscallHandler));
  if (!Storage) {
    Outcome={PEAR_FEX_UNAVAILABLE,0,0};
    FEXCore::Utils::PearFEXMemory::Retirement::PoisonSourceAdmission(Outcome); return {};
  }
  auto Actual=fextl::unique_ptr<DummySyscallHandler> {::new (Storage) DummySyscallHandler()};
  Outcome={PEAR_FEX_OK,0,0};return Actual;
}
fextl::unique_ptr<DummySignalDelegator> CreatePearSignalDelegator(FEXCore::Utils::PearFEXMemory::Result& Outcome) {
  auto* Storage=FEXCore::Allocator::aligned_alloc(alignof(DummySignalDelegator),sizeof(DummySignalDelegator));
  if (!Storage) {
    Outcome={PEAR_FEX_UNAVAILABLE,0,0};
    FEXCore::Utils::PearFEXMemory::Retirement::PoisonSourceAdmission(Outcome); return {};
  }
  auto Actual=fextl::unique_ptr<DummySignalDelegator> {::new (Storage) DummySignalDelegator()};
  Outcome={PEAR_FEX_OK,0,0};return Actual;
}
#endif

} // namespace FEX::DummyHandlers
