// SPDX-License-Identifier: MIT
// Original Pear finite link layout checks around the retained FEX instruction
// builders. These helpers only consume/calculate private NX values.
#pragma once
#include "Interface/Context/Context.h"
#include "Interface/Core/ArchHelpers/Arm64Emitter.h"
#include "Interface/Core/PearJITMetadata.h"
#include <array>
#include <algorithm>
#include <cstring>

namespace FEXCore::CPU::PearJITLinkLayout {
inline constexpr size_t THUNK_BYTES = 16+sizeof(FEXCore::Context::ExitFunctionLinkData);
inline constexpr size_t CALLER_BYTES = 12;
struct Layout {
  size_t ThunkOffset {}, RecordOffset {}, CallerOffset {}, MarkerOffset {};
  size_t WriteOffset {}, WriteSize {};
};
inline bool Contains(size_t Begin, size_t Size, size_t Offset, size_t Bytes) {
  return Offset >= Begin && Offset-Begin <= Size && Bytes <= Size-(Offset-Begin);
}
inline bool Build(uintptr_t Base, size_t Usable, uintptr_t RecordAddress,
                  const FEXCore::Context::ExitFunctionLinkData& Record, Layout& Out) {
  if (!Base || !Usable || Base > UINTPTR_MAX-Usable || RecordAddress < Base ||
      RecordAddress-Base < 16 || (RecordAddress & 7)) return false;
  const auto Thunk = RecordAddress-16;
  uint64_t Caller {};
  if (!FEXCore::CPU::PearJITMetadata::Advance(Thunk, static_cast<uint64_t>(Record.CallerOffset), Base, Base+Usable, Caller) ||
      Caller < Base || Caller-Base < 8 || Caller >= Thunk || 4 > Thunk-Caller || (Caller & 3) || (Thunk & 3)) return false;
  Layout L {.ThunkOffset = Thunk-Base, .RecordOffset = RecordAddress-Base, .CallerOffset = Caller-Base, .MarkerOffset = Caller-Base-8};
  if (!Contains(0, Usable, L.ThunkOffset, THUNK_BYTES) || !Contains(0, Usable, L.MarkerOffset, CALLER_BYTES)) return false;
  L.WriteOffset = std::min(L.ThunkOffset, L.MarkerOffset);
  const auto End = std::max(L.ThunkOffset+THUNK_BYTES, L.MarkerOffset+CALLER_BYTES);
  L.WriteSize = End-L.WriteOffset;
  if (!L.WriteSize || L.WriteSize > FEXCore::CPU::PearJITMetadata::MAX_SOURCE_BLOCK_BYTES) return false;
  Out = L; return true;
}
struct Instructions {
  bool Direct {}, Call {};
  uint32_t KnownCallMarker {}, PatchedWord {}, RestoreWord {};
};
inline Instructions Encode(uintptr_t Base, const Layout& L, uintptr_t HostCode, uint32_t Marker) {
  Instructions I;
  ARMEmitter::Emitter Known(reinterpret_cast<uint8_t*>(&I.KnownCallMarker), 4);
  Known.adr(TMP1, 0xc);
  const auto Caller = Base+L.CallerOffset, Thunk = Base+L.ThunkOffset;
  const auto Offset = HostCode/4-Caller/4;
  I.Direct = ARMEmitter::Emitter::IsInt26(Offset); I.Call = Marker == I.KnownCallMarker;
  ARMEmitter::Emitter Patched(reinterpret_cast<uint8_t*>(&I.PatchedWord), 4);
  ARMEmitter::Emitter Restored(reinterpret_cast<uint8_t*>(&I.RestoreWord), 4);
  if (I.Direct) {
    if (I.Call) { Patched.bl(Offset); Restored.bl(Thunk/4-Caller/4); }
    else { Patched.b(Offset); Restored.b(Thunk/4-Caller/4); }
  } else {
    // Preserve the actual upstream literal-load and restoration formulas.
    Patched.ldr(TMP1, Base+L.RecordOffset+offsetof(FEXCore::Context::ExitFunctionLinkData, HostCode)-Thunk);
    Restored.b(0x2);
  }
  return I;
}
inline bool UnlinkedSourceMatches(uintptr_t Base,const Layout& L,const Instructions& I,
                                  const std::array<uint8_t,THUNK_BYTES>& Thunk,
                                  const std::array<uint8_t,CALLER_BYTES>& Caller) {
  uint32_t CallerWord {},First {},Second {},Third {},Fourth {},ExpectedCaller {},ExpectedBR {},ExpectedBLR {};
  std::memcpy(&CallerWord,Caller.data()+8,4);
  std::memcpy(&First,Thunk.data(),4); std::memcpy(&Second,Thunk.data()+4,4);
  std::memcpy(&Third,Thunk.data()+8,4); std::memcpy(&Fourth,Thunk.data()+12,4);
  ARMEmitter::Emitter C(reinterpret_cast<uint8_t*>(&ExpectedCaller),4);
  if (I.Call) C.bl((Base+L.ThunkOffset)/4-(Base+L.CallerOffset)/4);
  else C.b((Base+L.ThunkOffset)/4-(Base+L.CallerOffset)/4);
  ARMEmitter::Emitter BR(reinterpret_cast<uint8_t*>(&ExpectedBR),4); BR.br(TMP1);
  ARMEmitter::Emitter BLR(reinterpret_cast<uint8_t*>(&ExpectedBLR),4); BLR.blr(TMP1);
  // Match the actual appended pending-thunk shape before it can mint an owned
  // descriptor. Literal displacement remains the actual emitted source byte.
  return CallerWord==ExpectedCaller && First==0x14000002 && Second==ExpectedBR &&
    (Third&0xff000000)==0x58000000 && Fourth==ExpectedBLR;
}
} // namespace FEXCore::CPU::PearJITLinkLayout
