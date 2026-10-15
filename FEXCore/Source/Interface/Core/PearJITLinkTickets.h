// SPDX-License-Identifier: MIT
// Original finite NX source ticket bookkeeping. No owner/VM/code permission.
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
namespace FEXCore::CPU::PearJITLinks {
inline constexpr size_t CAPACITY = 64;
enum class State : uint8_t { Free, Prepared, Linked, Pending, InFlight, Failed };
// These state functions are also called by finite NX metadata controls. They
// grant no owner permission, executable pointer, actual descriptor or lifecycle.
class TicketLedger {
public:
  struct Ticket { size_t Index {}; uint64_t Value {}; };
  struct Entry { size_t Index {}; uint64_t Value {}; };
  std::optional<Ticket> Prepare() {
    if (Next == UINT64_MAX) { Closed=true; return std::nullopt; }
    if (Closed || Batch || HasSealedEntries()) return std::nullopt;
    for (const auto& R : Records) if (R.Kind == State::Prepared) return std::nullopt;
    for (size_t I=0; I<CAPACITY; ++I) if (Records[I].Kind == State::Free) {
      Records[I] = {++Next, State::Prepared}; return Ticket {I, Next};
    }
    Closed = true; return std::nullopt;
  }
  bool Commit(Ticket T) { return Transition(T, State::Prepared, State::Linked); }
  bool CancelPrepared(Ticket T) {
    if (!Match(T, State::Prepared)) return Close();
    Records[T.Index] = {}; return true;
  }
  bool BeginBatch() {
    if (Closed || Batch || HasSealedEntries()) return false;
    for (const auto& R : Records) if (R.Kind == State::Prepared || R.Kind == State::InFlight || R.Kind == State::Failed) return false;
    Batch = true; return true;
  }
  bool Queue(Ticket T) {
    if (!Batch || T.Index>=CAPACITY || Records[T.Index].Value!=T.Value || !T.Value) return Close();
    if (Records[T.Index].Kind == State::Pending) return true;
    return Transition(T, State::Linked, State::Pending);
  }
  std::optional<Ticket> Take(size_t I) {
    if (!Batch || I>=CAPACITY || Records[I].Kind != State::Pending) return std::nullopt;
    Records[I].Kind = State::InFlight; return Ticket {I, Records[I].Value};
  }
  bool Complete(Ticket T, bool ObservedPublication) {
    if (!Match(T, State::InFlight)) return Close();
    if (!ObservedPublication) { Records[T.Index].Kind = State::Failed; return Close(); }
    Records[T.Index] = {}; return true;
  }
  bool FinishBatch() {
    if (!Batch || Closed) return false;
    for (const auto& R : Records) if (R.Kind == State::Pending || R.Kind == State::InFlight || R.Kind == State::Failed) return false;
    Batch = false; return true;
  }
  bool EntryAdmissionOpen() const {
    if (Closed || Batch) return false;
    for (const auto& R : Records) if (R.Kind == State::Prepared) return false;
    return true;
  }
  std::optional<Entry> SealEntry() {
    if (!EntryAdmissionOpen() || Next == UINT64_MAX) {
      if (Next == UINT64_MAX) Closed=true;
      return std::nullopt;
    }
    for (size_t I=0;I<CAPACITY;++I) if (!Entries[I]) {
      Entries[I]=++Next; return Entry {I,Entries[I]};
    }
    return std::nullopt;
  }
  bool MatchEntry(Entry E) const { return E.Value && E.Index<CAPACITY && Entries[E.Index]==E.Value; }
  bool ReleaseEntry(Entry E) {
    if (!MatchEntry(E)) return Close();
    Entries[E.Index]=0; return true;
  }
  bool HasSealedEntries() const { for (const auto E:Entries) if (E) return true; return false; }
  State GetState(size_t I) const { return I<CAPACITY ? Records[I].Kind : State::Failed; }
  uint64_t GetTicket(size_t I) const { return I<CAPACITY ? Records[I].Value : 0; }
  size_t Occupied() const { size_t N{}; for (const auto& R:Records) N += R.Kind != State::Free; return N; }
  bool Close() { Closed=true; return false; }
private:
  struct Record { uint64_t Value{}; State Kind{State::Free}; };
  bool Match(Ticket T, State S) const { return T.Value && T.Index<CAPACITY && Records[T.Index].Value==T.Value && Records[T.Index].Kind==S; }
  bool Transition(Ticket T, State From, State To) {
    if (!Match(T, From)) return Close();
    Records[T.Index].Kind=To; return true;
  }
  std::array<Record,CAPACITY> Records {};
  std::array<uint64_t,CAPACITY> Entries {};
  uint64_t Next {};
  bool Closed {}, Batch {};
};
} // namespace FEXCore::CPU::PearJITLinks
