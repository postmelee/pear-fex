// SPDX-FileCopyrightText: 2026 Pear contributors
// SPDX-License-Identifier: MIT
namespace PearSlot {
Row Snapshot(uint64_t context,uint64_t source) {
  using namespace FEXCore::Utils::PearFEXMemory;
  Row out {};
  // Use the same registry lock word once, without spinning or reentrant wait.
  // No callback, bridge, allocation, source dereference or output while held.
  const auto self=reinterpret_cast<uintptr_t>(GetCurrentTEB());
  uintptr_t empty=0;
  if (!Registry.compare_exchange_strong(empty,self,std::memory_order_acquire,std::memory_order_relaxed)) {
    out.Snapshot=2; return out;
  }
  const auto* found=static_cast<const Binding*>(nullptr);
  if (!context && !source) found=CurrentBinding();
  else for (const auto& b:Bindings) {
    if (b.TEB && (!context || reinterpret_cast<uint64_t>(b.SourceContext)==context) &&
        (!source || reinterpret_cast<uint64_t>(b.SourceState)==source)) { found=&b; break; }
  }
  if (found) {
    out.Context=reinterpret_cast<uint64_t>(found->SourceContext);
    out.Source=reinterpret_cast<uint64_t>(found->SourceState);
    out.Serial=found->LifetimeSerial;out.Executor=found->Executor;
    out.Holds=found->LifetimeHolds;out.Snapshot=1;
    out.Flags=(found->Pending?1u:0u)|(found->Capturing?2u:0u)|(found->Unresolved?4u:0u)|
      (found->CleanupAttempted?8u:0u)|(found->LifetimeClosing?16u:0u)|
      (found->LifetimeDeleteSealed?32u:0u)|(found->CleanupOnly?64u:0u);
  }
  Registry.store(0,std::memory_order_release);
  return out;
}
}
