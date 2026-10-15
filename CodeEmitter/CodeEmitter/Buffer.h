// SPDX-License-Identifier: MIT
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>
#ifdef PEAR_FEX_MEMORY_OWNER
#include <FEXCore/Utils/PearSourceGuard.h>
#include <FEXCore/Utils/LogManager.h>
#endif

namespace ARMEmitter {
class Buffer {
public:
  Buffer() {
    SetBuffer(nullptr, 0);
  }

  Buffer(uint8_t* Base, uint64_t BaseSize) {
    SetBuffer(Base, BaseSize);
  }

  void SetBuffer(uint8_t* Base, uint64_t BaseSize) {
#ifdef PEAR_FEX_MEMORY_OWNER
    PEAR_FEX_REQUIRE((Base || !BaseSize) && BaseSize <= SIZE_MAX &&
                      (!Base || reinterpret_cast<uintptr_t>(Base) <= UINTPTR_MAX - BaseSize),
                      "Pear emitter buffer geometry is invalid");
#endif
    BufferBase = Base;
    CurrentOffset = BufferBase;
    Size = BaseSize;
  }

  template<typename T>
  requires (std::is_trivially_copyable_v<T>)
  void dcn(const T& Data) {
#ifdef PEAR_FEX_MEMORY_OWNER
    CheckRange(CurrentOffset, sizeof(Data));
#endif
    std::memcpy(CurrentOffset, &Data, sizeof(Data));
    CurrentOffset += sizeof(Data);
  }
  void dc8(uint8_t Data) {
    dcn(Data);
  }
  void dc16(uint16_t Data) {
    dcn(Data);
  }
  void dc32(uint32_t Data) {
    dcn(Data);
  }
  void dc64(uint64_t Data) {
    dcn(Data);
  }

  void EmitString(const char* String) {
#ifdef PEAR_FEX_MEMORY_OWNER
    PEAR_FEX_REQUIRE(String, "Pear emitter string is unavailable");
#endif
    const auto StringLength = strlen(String);
#ifdef PEAR_FEX_MEMORY_OWNER
    CheckRange(CurrentOffset, StringLength);
#endif
    memcpy(CurrentOffset, String, StringLength);
    CurrentOffset += StringLength;
  }

  void Align(size_t Size = 4) {
#ifdef PEAR_FEX_MEMORY_OWNER
    PEAR_FEX_REQUIRE(Size && !(Size & (Size - 1)), "Pear emitter alignment is invalid");
    CheckRange(CurrentOffset, 0);
#endif
    // Align the buffer to provided size.
    auto CurrentAlignment = reinterpret_cast<uint64_t>(CurrentOffset) & (Size - 1);
    if (!CurrentAlignment) {
      return;
    }
#ifdef PEAR_FEX_MEMORY_OWNER
    CheckRange(CurrentOffset, Size - CurrentAlignment);
#endif
    std::memset(CurrentOffset, 0, Size - CurrentAlignment);
    CurrentOffset += Size - CurrentAlignment;
  }

  template<typename T>
  T GetCursorAddress() const {
    return reinterpret_cast<T>(CurrentOffset);
  }

  static void ClearICache(void* Begin, std::size_t Length) {
    __builtin___clear_cache(static_cast<char*>(Begin), static_cast<char*>(Begin) + Length);
  }

  size_t GetCursorOffset() const {
#ifdef PEAR_FEX_MEMORY_OWNER
    CheckRange(CurrentOffset, 0);
    return static_cast<size_t>(reinterpret_cast<uintptr_t>(CurrentOffset) - reinterpret_cast<uintptr_t>(BufferBase));
#else
    return static_cast<size_t>(CurrentOffset - BufferBase);
#endif
  }

  uint8_t* GetBufferBase() const {
    return BufferBase;
  }

  void CursorIncrement(size_t Size) {
#ifdef PEAR_FEX_MEMORY_OWNER
    CheckRange(CurrentOffset, Size);
#endif
    CurrentOffset += Size;
  }

  void SetCursorOffset(size_t Offset) {
#ifdef PEAR_FEX_MEMORY_OWNER
    PEAR_FEX_REQUIRE(Offset <= Size && (BufferBase || !Offset), "Pear emitter cursor is outside its buffer");
#endif
    CurrentOffset = BufferBase + Offset;
  }

  uint64_t GetBufferSize() const {
    return Size;
  }

  template<typename T>
  size_t GetCursorOffsetFromAddress(const T* Address) const {
#ifdef PEAR_FEX_MEMORY_OWNER
    CheckRange(Address, 0);
    return static_cast<size_t>(reinterpret_cast<uintptr_t>(Address) - reinterpret_cast<uintptr_t>(BufferBase));
#else
    return static_cast<size_t>(reinterpret_cast<const uint8_t*>(Address) - BufferBase);
#endif
  }

protected:
#ifdef PEAR_FEX_MEMORY_OWNER
  // Used before every source emitter write and label read/backpatch. A numeric
  // check cannot grant permissions; callers still need the owner WriteGuard.
  void CheckRange(const void* Pointer, size_t Bytes) const {
    const auto Base = reinterpret_cast<uintptr_t>(BufferBase);
    const auto Address = reinterpret_cast<uintptr_t>(Pointer);
    const bool Empty = !Base && !Address && !Size && !Bytes;
    const bool Fits = Base && Address >= Base && Address - Base <= Size && Bytes <= Size - (Address - Base);
    PEAR_FEX_REQUIRE(Empty || Fits, "Pear emitter read/write exceeds its source buffer");
  }
#endif

  uint8_t* BufferBase;
  uint8_t* CurrentOffset;
  uint64_t Size;
};
} // namespace ARMEmitter
