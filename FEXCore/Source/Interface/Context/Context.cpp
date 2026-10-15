// SPDX-License-Identifier: MIT
#ifdef PEAR_FEX_MEMORY_OWNER
#include <FEXCore/Utils/PearDataMemory.h>
#endif
#include <FEXCore/Utils/PearSourceGuard.h>
#include "Interface/Context/Context.h"
#include "Interface/Core/OpcodeDispatcher.h"
#include "Interface/Core/Dispatcher/Dispatcher.h"
#include "Interface/Core/X86Tables/X86Tables.h"

#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CPUID.h>
#include <FEXCore/Core/HostFeatures.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/HLE/SyscallHandler.h>
#ifdef PEAR_FEX_MEMORY_OWNER
#include <FEXCore/Utils/PearFEXRetirement.h>
#endif

#include <FEXCore/Core/Thunks.h>
#include "FEXCore/Debug/InternalThreadState.h"

namespace FEXCore::Context {
#ifdef PEAR_FEX_MEMORY_OWNER
PearContextOwner FEXCore::Context::Context::CreateNewContext(const FEXCore::HostFeatures& Features) {
  FEXCore::Utils::PearFEXMemory::Result Outcome;
  return CreatePearContext(Features,Outcome);
}
PearContextOwner FEXCore::Context::Context::CreatePearContext(const FEXCore::HostFeatures& Features,
    FEXCore::Utils::PearFEXMemory::Result& Outcome) {
  // Reuse the selected allocator/alignment once, but never placement-construct
  // a real Context into a null allocation. No errno is invented for rpaligned_alloc.
  auto* Storage=FEXCore::Allocator::AllocatePearMetadataStorage(alignof(FEXCore::Context::ContextImpl),sizeof(FEXCore::Context::ContextImpl));
  if (!Storage) {
    Outcome={PEAR_FEX_UNAVAILABLE,0,0};
    FEXCore::Utils::PearFEXMemory::Retirement::PoisonSourceAdmission(Outcome);
    return {};
  }
  auto Actual=fextl::unique_ptr<FEXCore::Context::ContextImpl> {
    ::new (Storage) FEXCore::Context::ContextImpl(Features)};
  Outcome=Actual->GetPearLifetimeCreation();
  if (!Outcome) {
    // This actual allocation was never admitted, bound or initialized. Its
    // upstream NX fields can be destroyed by the still-owned original deleter.
    FEXCore::Utils::PearFEXMemory::Retirement::PoisonSourceAdmission(Outcome); return {};
  }
  return PearContextOwner {Actual.release()};
}
bool Context::DestroyPearContextChecked(PearContextOwner& Owner, FEXCore::Utils::PearFEXMemory::Result& Outcome,
                                       bool& Destroyed, bool& Freed) {
  return ContextImpl::DestroyPearContextBackingChecked(Owner,Outcome,Destroyed,Freed);
}
bool ContextImpl::DestroyPearContextBackingChecked(PearContextOwner& Owner, FEXCore::Utils::PearFEXMemory::Result& Outcome,
                                                  bool& Destroyed, bool& Freed) {
  namespace Memory=FEXCore::Utils::PearFEXMemory;
  Destroyed=false; Freed=false;
  auto* Actual=Owner.get();
  if (!Actual) { Outcome={PEAR_FEX_INVALID_REQUEST,0,0}; return false; }
  if (!Actual->PreparePearConstructionCleanup(Outcome)) {
    Memory::SourceLifecycle::Retain(Actual,Outcome); return false;
  }
  Outcome=Memory::SourceLifecycle::BeginContextDestruction(Actual);
  if (!Outcome) { Memory::SourceLifecycle::Retain(Actual,Outcome); return false; }
  // Consume C++ deletion ownership once before destructor execution. If the
  // later identity completion refuses, the actual backing is already destroyed
  // and must not be retried through a dangling unique_ptr.
  Owner.release();
  std::destroy_at(Actual); Destroyed=true;
  Outcome=Memory::SourceLifecycle::Deleted(Actual);
  if (!Outcome) { Memory::SourceLifecycle::RetainDestroyed(Actual,Outcome); return false; }
  FEXCore::Allocator::FreePearMetadataOrHeap(Actual); Freed=true;
  return true;
}
void PearContextDeleter::operator()(Context* Actual) const {
  if (!Actual) return;
  PearContextOwner Owner {Actual};
  FEXCore::Utils::PearFEXMemory::Result Outcome;
  bool Destroyed {},Freed {};
  (void)Context::DestroyPearContextChecked(Owner,Outcome,Destroyed,Freed);
  // A known alive refusal is retained by SourceLifecycle. Prevent recursive
  // unique_ptr deletion and keep dependencies for the original refusal.
  if (Owner) Owner.release();
}
#else
fextl::unique_ptr<FEXCore::Context::Context> FEXCore::Context::Context::CreateNewContext(const FEXCore::HostFeatures& Features) {
  return fextl::make_unique<FEXCore::Context::ContextImpl>(Features);
}
#endif

void FEXCore::Context::ContextImpl::CompileRIP(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto Life=FEXCore::Utils::PearFEXMemory::AcquireCurrentSourceLifetime(this);
  PEAR_FEX_REQUIRE(Life && Life.ActualThread()==Thread && Life.Validate(),"Pear source Thread lifetime is unavailable");
#endif

  CompileBlock(Thread->CurrentFrame, GuestRIP);
}

void FEXCore::Context::ContextImpl::CompileRIPCount(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP, uint64_t MaxInst) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto Life=FEXCore::Utils::PearFEXMemory::AcquireCurrentSourceLifetime(this);
  PEAR_FEX_REQUIRE(Life && Life.ActualThread()==Thread && Life.Validate(),"Pear source Thread lifetime is unavailable");
#endif

  CompileBlock(Thread->CurrentFrame, GuestRIP, MaxInst);
}

void FEXCore::Context::ContextImpl::SetSignalDelegator(FEXCore::SignalDelegator* _SignalDelegation) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto Life=FEXCore::Utils::PearFEXMemory::SourceLifecycle::HoldContext(this);
  PEAR_FEX_REQUIRE(!!Life,"Pear source Context lifetime is unavailable");
#endif

  SignalDelegation = _SignalDelegation;
}

void FEXCore::Context::ContextImpl::SetSyscallHandler(FEXCore::HLE::SyscallHandler* Handler) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto Life=FEXCore::Utils::PearFEXMemory::SourceLifecycle::HoldContext(this);
  PEAR_FEX_REQUIRE(!!Life,"Pear source Context lifetime is unavailable");
#endif

  SyscallHandler = Handler;
  SourcecodeResolver = Handler->GetSourcecodeResolver();
}

void FEXCore::Context::ContextImpl::SetThunkHandler(FEXCore::ThunkHandler* Handler) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto Life=FEXCore::Utils::PearFEXMemory::SourceLifecycle::HoldContext(this);
  PEAR_FEX_REQUIRE(!!Life,"Pear source Context lifetime is unavailable");
#endif

  ThunkHandler = Handler;
}

FEXCore::CPUID::FunctionResults FEXCore::Context::ContextImpl::RunCPUIDFunction(uint32_t Function, uint32_t Leaf) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto Life=FEXCore::Utils::PearFEXMemory::SourceLifecycle::HoldContext(this);
  PEAR_FEX_REQUIRE(!!Life,"Pear source Context lifetime is unavailable");
#endif

  return CPUID.RunFunction(Function, Leaf);
}

FEXCore::CPUID::XCRResults FEXCore::Context::ContextImpl::RunXCRFunction(uint32_t Function) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto Life=FEXCore::Utils::PearFEXMemory::SourceLifecycle::HoldContext(this);
  PEAR_FEX_REQUIRE(!!Life,"Pear source Context lifetime is unavailable");
#endif

  return CPUID.RunXCRFunction(Function);
}

FEXCore::CPUID::FunctionResults FEXCore::Context::ContextImpl::RunCPUIDFunctionName(uint32_t Function, uint32_t Leaf, uint32_t CPU) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto Life=FEXCore::Utils::PearFEXMemory::SourceLifecycle::HoldContext(this);
  PEAR_FEX_REQUIRE(!!Life,"Pear source Context lifetime is unavailable");
#endif

  return CPUID.RunFunctionName(Function, Leaf, CPU);
}

bool FEXCore::Context::ContextImpl::IsAddressInCodeBuffer(FEXCore::Core::InternalThreadState* Thread, uintptr_t Address) const {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto Life=FEXCore::Utils::PearFEXMemory::AcquireCurrentSourceLifetime(this);
  PEAR_FEX_REQUIRE(Life && Life.ActualThread()==Thread && Life.Validate(),"Pear source Thread lifetime is unavailable");
#endif

  return Thread->CPUBackend->IsAddressInCodeBuffer(Address) || CodeCache.IsAddressInMappedCodeBuffer(Address);
}

bool FEXCore::Context::ContextImpl::RequiresRelocatableConstants() const {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto Life=FEXCore::Utils::PearFEXMemory::SourceLifecycle::HoldContext(this);
  PEAR_FEX_REQUIRE(!!Life,"Pear source Context lifetime is unavailable");
#endif

  // Support relocation when generating a cache or when generating reference code for validation
  return CodeCache.IsGeneratingCache || FEXCore::Config::Get_ENABLECODECACHEVALIDATION() || DiskCache.IsWritingDiskCache();
}

} // namespace FEXCore::Context
