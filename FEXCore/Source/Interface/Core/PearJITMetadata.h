// SPDX-License-Identifier: MIT
// Original Pear bounds around the selected upstream JIT metadata/decoder.
#pragma once
#include "Interface/Core/CPUBackend.h"
#include "Utils/variable_length_integer.h"
#include <optional>
#include <span>

namespace FEXCore::CPU::PearJITMetadata {
inline constexpr size_t MAX_SOURCE_BLOCK_BYTES = 16ULL * 1024 * 1024;
inline constexpr size_t MAX_PAIR_BYTES = 17;
inline bool HeaderRange(const CPUBackend::JITCodeHeader& Header, size_t Available) {
  return Header.OffsetToBlockTail <= MAX_SOURCE_BLOCK_BYTES && Header.OffsetToBlockTail >= sizeof(Header) && !(Header.OffsetToBlockTail % alignof(CPUBackend::JITCodeTail)) &&
    Header.OffsetToBlockTail <= Available && sizeof(CPUBackend::JITCodeTail) <= Available-Header.OffsetToBlockTail;
}
inline bool TailRange(const CPUBackend::JITCodeHeader& Header, const CPUBackend::JITCodeTail& Tail, size_t Available) {
  if (!HeaderRange(Header, Available) || !Tail.Size || Tail.Size > MAX_SOURCE_BLOCK_BYTES || Tail.Size > Available ||
      Header.OffsetToBlockTail > Tail.Size || sizeof(Tail) > Tail.Size-Header.OffsetToBlockTail ||
      Tail.GuestSize > UINT64_MAX-Tail.RIP) return false;
  const auto AfterTail = Tail.Size-Header.OffsetToBlockTail;
  return Tail.OffsetToRIPEntries >= sizeof(Tail) && Tail.OffsetToRIPEntries <= AfterTail &&
    Tail.NumberOfRIPEntries <= AfterTail-Tail.OffsetToRIPEntries;
}
inline size_t PairSize(uint8_t Header) {
  if (!(Header & 0x80)) return 1;
  if ((Header & 0xc0) == 0x80) return 2;
  if (Header == 0xc0) return 9;
  if (Header == 0xe0) return 17;
  return 0;
}
inline std::optional<FEXCore::Utils::vl64pair::Decoded> DecodePair(std::span<const uint8_t> Bytes) {
  if (Bytes.empty()) return std::nullopt;
  const auto Size = PairSize(Bytes.front());
  if (!Size || Bytes.size() < Size) return std::nullopt;
  // Reuse the actual upstream decoder after its complete read footprint is
  // known and present in this private NX record. No managed pointer is passed.
  const auto Decoded = FEXCore::Utils::vl64pair::Decode(Bytes.data());
  return Decoded.Size == Size ? std::optional {Decoded} : std::nullopt;
}
inline bool Advance(uint64_t Current, uint64_t EncodedDelta, uint64_t Begin, uint64_t End, uint64_t& Next) {
  if (Current < Begin || Current > End) return false;
  if (!(EncodedDelta & (uint64_t {1} << 63))) {
    if (EncodedDelta > End-Current) return false;
    Next = Current+EncodedDelta;
  } else {
    const uint64_t Magnitude = 0-EncodedDelta;
    if (Magnitude > Current-Begin) return false;
    Next = Current-Magnitude;
  }
  return true;
}
} // namespace FEXCore::CPU::PearJITMetadata
