// SPDX-License-Identifier: MIT
// Actual selected FEX configuration under ordinary ARM64 MinGW CRT.
// No FEX Context, Thread, JIT owner, translated code or guest execution.
#include <FEXCore/Config/Config.h>
#include "Common/DarwinConfigPolicy.h"
#include <rpmalloc/rpmalloc.h>
#include <windows.h>
#include <cstdio>
namespace {
void require(bool Value,unsigned Step) {
  if (!Value) {std::printf("{\"record_kind\":\"pear_config_failure\",\"step\":%u}\n",Step);std::fflush(stdout);ExitProcess(Step);}
}
void read_policy() {
  using namespace FEXCore::Config;
  for (auto Option:{CONFIG_DISKCACHE,CONFIG_PROFILESTATS,CONFIG_ENABLECODECACHINGWIP,
                    CONFIG_ENABLELAZYCODECACHINGWIP,CONFIG_ENABLECODECACHEVALIDATION,
                    CONFIG_KERNELUNALIGNEDATOMICBACKPATCHING})
    require(GetConv<bool>(Option)==false,31);
  for (auto Option:{CONFIG_TSOENABLED,CONFIG_VECTORTSOENABLED,CONFIG_MEMCPYSETTSOENABLED,
                    CONFIG_HALFBARRIERTSOENABLED,CONFIG_STRICTINPROCESSSPLITLOCKS})
    require(GetConv<bool>(Option)==true,32);
  require(GetConv<uint64_t>(CONFIG_HOSTFEATURES)==0,33);
}
}
int main() {
  namespace C=FEXCore::Config;
  require(rpmalloc_initialize(nullptr)==0,1);
  // The ordinary configuration still uses its real heap-backed source path.
  C::Initialize();require(FEX::Windows::DarwinPolicy::Apply(),2);read_policy();
  bool Created=true;require(!C::InitializePearEmpty(Created) && !Created,3);
  read_policy();C::Shutdown();
  require(C::InitializePearEmpty(Created) && Created,4);
  bool Second=true;require(!C::InitializePearEmpty(Second) && !Second,5);
  require(!C::SealPearEmpty(),6); // Incomplete policy is a typed refusal.
  require(FEX::Windows::DarwinPolicy::Apply(),7);
  C::Set(C::CONFIG_INTERPRETER_INSTALLED,"0");C::Set(C::CONFIG_IS64BIT_MODE,"0");
  require(C::SealPearEmpty(),8);read_policy();
  require(C::GetConv<bool>(C::CONFIG_INTERPRETER_INSTALLED)==false &&
          C::GetConv<bool>(C::CONFIG_IS64BIT_MODE)==false,9);
  require(!C::Exists(C::CONFIG_ROOTFS) && !C::Get(C::CONFIG_ROOTFS),10);
  const auto Bytes=C::PearEmptyStorageBytes();require(Bytes<=4352,11);
  require(C::ShutdownPearEmpty(),12);require(!C::ShutdownPearEmpty(),13);
  Created=true;require(!C::InitializePearEmpty(Created) && !Created,14);
  rpmalloc_thread_finalize();
  std::printf("{\"record_kind\":\"pear_config_terminal\",\"passed\":true,\"settings\":14,\"storage_bytes\":%llu,\"original_profile_verified\":true,\"incomplete_seal_refused\":true,\"cleanup_verified\":true,\"reuse_refused\":true,\"engine_initialized\":false}\n",static_cast<unsigned long long>(Bytes));
  return 0;
}
