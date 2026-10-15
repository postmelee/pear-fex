// SPDX-License-Identifier: MIT
// Original finite downstream helper. The historical void CRT API is retained.
#pragma once
#include <cstddef>
#include <cstdint>
#include <windef.h>
#include "Report.h"
#include "wine/pear_fex_memory.h"

namespace FEX::Windows::PearEmptyInit {
// The plan contains NX callback pointers only and is retained lexically until
// actual source objects finish cleanup. It is never permission or a fake TLS.
struct CRTPlan {
  // The pinned ordinary image has two FEX and six GNU callbacks. Keep a small
  // explicit headroom while refusing larger/unreviewed callback tables before
  // constructors. This bounds both persistent entries and GNU inspection scratch.
  static constexpr size_t MAX_CALLBACKS=16;
  enum class Kind : uint32_t { FEX, GNU, XI, XC, XL };
  struct Callback { uintptr_t Address {}; Kind Group {}; };
  Callback Entries[MAX_CALLBACKS] {};
  size_t Count {};
  HMODULE CurrentImage {}, NtDll {};
  uint64_t NativeOwnerPID {};
  pear_fex_memory_metadata Metadata {};
  const wchar_t* Environment {};
  size_t EnvironmentCharacters {};
  bool ProcessReturned {}, ThreadReturned {};
};
static_assert(sizeof(CRTPlan)<=4352,"Finite selected CRT snapshot; aggregate proof is separate");
// Finite prerequisite observation only: image/TLS/environment/native PID and
// temporary idle-owner registration/observation/unregister. No CRT constructor,
// FEX object, executable extent, source binding or generated-code entry.
Outcome InspectPrerequisites(CRTPlan&,Report&);
Outcome InspectBeforeInitialization(CRTPlan&,Report&);
Outcome InitializeCheckedProcess(CRTPlan&,Report&);
Outcome InitializeCheckedThread(CRTPlan&,Report&);
Outcome FinalizeCheckedThread(CRTPlan&,Report&);
Outcome ObserveHostBasics(uint32_t& ProcessorCount,uint32_t& PageSize);
} // namespace FEX::Windows::PearEmptyInit
