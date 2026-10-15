// SPDX-License-Identifier: MIT
/*
$info$
meta: ir|opts ~ IR to IR Optimization
tags: ir|opts
desc: Defines which passes are run, and runs them
$end_info$
*/

#include "Interface/Context/Context.h"
#include "Interface/IR/PassManager.h"
#include "Interface/IR/Passes.h"
#include "Interface/IR/Passes/RegisterAllocationPass.h"

#include <FEXCore/Config/Config.h>
#ifdef PEAR_FEX_MEMORY_OWNER
#include <FEXCore/Utils/PearDataMemory.h>
#include <FEXCore/Utils/PearSourceGuard.h>
#endif
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/Profiler.h>

namespace FEXCore::IR {
class IREmitter;

#ifdef PEAR_FEX_MEMORY_OWNER
fextl::unique_ptr<PassManager> PassManager::CreatePear(Context::ContextImpl* CTX,FEXCore::Utils::PearFEXMemory::Result& Outcome) {
  Outcome={PEAR_FEX_UNAVAILABLE,0,0};
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
  return {}; // Validation-pass insertion is not the selected finite pipeline.
#else
  void* Storage=FEXCore::Allocator::AllocatePearMetadataStorage(alignof(PassManager),sizeof(PassManager));
  if (!Storage) return {};
  fextl::unique_ptr<PassManager> Actual {::new (Storage) PassManager(PearEmptyTag {})};
  if (Actual->PassManagerDumpIR()) return {};
  auto Append=[&](fextl::unique_ptr<Pass> Next) {
    if (!Next) return false;
    PEAR_FEX_REQUIRE(Actual->PearCount<Actual->PearPasses.size(),"Finite pass count");
    Next->RegisterPassManager(Actual.get());
    Actual->PearPasses[Actual->PearCount++]=std::move(Next);
    return true;
  };
  FEX_CONFIG_OPT(DisablePasses,O0);
  if (!DisablePasses()) {
    if (!Append(CreatePearX87StackOptimizationPass(CTX->HostFeatures,CTX->Config.Is64BitMode ? IR::OpSize::i64Bit : IR::OpSize::i32Bit))) return {};
    if (!Append(CreatePearDeadFlagCalculationEliminination())) return {};
  }
  auto RA=CreatePearRegisterAllocationPass(&CTX->CPUID);
  if (!RA) return {};
  Actual->PearRA=RA.get();
  if (!Append(std::move(RA))) return {};
  Outcome={PEAR_FEX_OK,0,0};return Actual;
#endif
}
#endif
void PassManager::Finalize() {
#ifdef PEAR_FEX_MEMORY_OWNER
  if (PearFinite) {
    PEAR_FEX_REQUIRE(!PassManagerDumpIR(),"Finite pipeline does not insert dumping passes");
    return;
  }
#endif
  if (!PassManagerDumpIR()) {
    // Not configured to dump any IR, just return.
    return;
  }

  auto it = Passes.begin();
  // Walk the passes and add them where asked.
  if (PassManagerDumpIR() & FEXCore::Config::PassManagerDumpIR::BEFOREOPT) {
    // Insert at the start.
    it = InsertAt(it, Debug::CreateIRDumper());
    ++it; // Skip what we inserted.
  }

  if ((PassManagerDumpIR() & FEXCore::Config::PassManagerDumpIR::BEFOREPASS) ||
      (PassManagerDumpIR() & FEXCore::Config::PassManagerDumpIR::AFTERPASS)) {

    bool SkipFirstBefore = PassManagerDumpIR() & FEXCore::Config::PassManagerDumpIR::BEFOREOPT;
    for (; it != Passes.end();) {
      if (PassManagerDumpIR() & FEXCore::Config::PassManagerDumpIR::BEFOREPASS) {
        if (SkipFirstBefore) {
          // If we need to skip the first one, then continue.
          SkipFirstBefore = false;
          ++it;
          continue;
        }

        // Insert before
        it = InsertAt(it, Debug::CreateIRDumper());
        ++it; // Skip what we inserted.
      }

      ++it; // Skip current pass.
      if (PassManagerDumpIR() & FEXCore::Config::PassManagerDumpIR::AFTERPASS) {
        // Insert after
        it = InsertAt(it, Debug::CreateIRDumper());
        ++it; // Skip what we inserted.
      }
    }
  }
  if (PassManagerDumpIR() & FEXCore::Config::PassManagerDumpIR::AFTEROPT) {
    if (!(PassManagerDumpIR() & FEXCore::Config::PassManagerDumpIR::AFTERPASS)) {
      // Insert final IRDumper.
      InsertAt(Passes.end(), Debug::CreateIRDumper());
    }
  }
}

void PassManager::AddDefaultPasses(Context::ContextImpl* ctx) {
  FEX_CONFIG_OPT(DisablePasses, O0);

  // We only specifically disable optimization passes if desired, as IR output should
  // still be well-formed regardless of the modifications made to it.
  if (!DisablePasses()) {
    InsertPass(CreateX87StackOptimizationPass(ctx->HostFeatures, ctx->Config.Is64BitMode ? IR::OpSize::i64Bit : IR::OpSize::i32Bit));
    InsertPass(CreateDeadFlagCalculationEliminination());
  }

  InsertPass(IR::CreateRegisterAllocationPass(&ctx->CPUID), "RA");

#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
  InsertValidationPass(Validation::CreateIRValidation(), "IRValidation");
#endif
}

Pass* PassManager::InsertPass(fextl::unique_ptr<Pass> Pass, const fextl::string& Name) {
#ifdef PEAR_FEX_MEMORY_OWNER
  PEAR_FEX_REQUIRE(!PearFinite,"Finite pass pipeline cannot accept dynamic insertion");
#endif
  auto* PassPtr = InsertAt(Passes.end(), std::move(Pass))->get();
  AttemptNameMapping(Name, PassPtr);
  return PassPtr;
}

PassManager::PassArrayType::iterator PassManager::InsertAt(PassArrayType::iterator pos, fextl::unique_ptr<Pass> Pass) {
  Pass->RegisterPassManager(this);
  return Passes.insert(pos, std::move(Pass));
}

#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
void PassManager::InsertValidationPass(fextl::unique_ptr<Pass> Pass, const fextl::string& Name) {
  Pass->RegisterPassManager(this);
  auto* PassPtr = ValidationPasses.emplace_back(std::move(Pass)).get();
  AttemptNameMapping(Name, PassPtr);
}
#endif

void PassManager::Run(IREmitter* IREmit) {
#ifdef PEAR_FEX_MEMORY_OWNER
  if (PearFinite) {
    for (size_t I=0;I<PearCount;++I) PearPasses[I]->Run(IREmit);
    return;
  }
#endif
  FEXCORE_PROFILE_SCOPED("PassManager::Run");

  for (const auto& Pass : Passes) {
    Pass->Run(IREmit);
  }

#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
  for (const auto& Pass : ValidationPasses) {
    Pass->Run(IREmit);
  }
#endif
}

void PassManager::AttemptNameMapping(const fextl::string& Name, Pass* NewPass) {
  if (Name.empty()) {
    // Empty name is a 'don't care' case. e.g. Passes that just need to run,
    // but don't need to be actively looked up.
    return;
  }

  const auto Result = NameToPassMaping.emplace(Name, NewPass);
  LOGMAN_THROW_A_FMT(Result.second, "Tried to insert pass with name '{}'. But name is already used", Name);
}
} // namespace FEXCore::IR
