// SPDX-License-Identifier: MIT
// Fixed NX ticket metadata. No executable pointer, owner permission or VM policy.
#pragma once
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>
namespace FEXCore::CPU::PearJITLinks {
inline constexpr size_t CAPACITY = 131072;
inline constexpr size_t ENTRY_CAPACITY = 64;
enum class State : uint8_t { Free, Prepared, Linked, Pending, InFlight, Failed };
template<size_t Capacity,size_t EntryCapacity=ENTRY_CAPACITY> class BasicTicketLedger {
  static_assert(Capacity && Capacity%64==0 && EntryCapacity && EntryCapacity<=64);
public:
  struct Ticket { size_t Index {}; uint64_t Value {}; };
  struct Entry { size_t Index {}; uint64_t Value {}; };
  BasicTicketLedger() { FreeWords.fill(UINT64_MAX); }
  std::optional<Ticket> Prepare() {
    if (Next==UINT64_MAX) { Closed=true; return std::nullopt; }
    if (Closed || Batch || HasSealedEntries() || Count(State::Prepared)) return std::nullopt;
    for (size_t Word=0;Word<FreeWords.size();++Word) if (FreeWords[Word]) {
      const auto Bit=std::countr_zero(FreeWords[Word]);const size_t I=Word*64+Bit;
      FreeWords[Word]&=~(uint64_t{1}<<Bit);Records[I].Value=++Next;SetState(I,State::Prepared);return Ticket{I,Next};
    }
    Closed=true;return std::nullopt;
  }
  bool Commit(Ticket T) { return Transition(T,State::Prepared,State::Linked); }
  bool CancelPrepared(Ticket T) { if (!Match(T,State::Prepared))return Close();Free(T.Index);return true; }
  bool BeginBatch() {
    if (Closed || Batch || HasSealedEntries() || Count(State::Prepared) || Count(State::InFlight) || Count(State::Failed))return false;
    Batch=true;return true;
  }
  bool Queue(Ticket T) {
    if (!Batch || T.Index>=Capacity || Records[T.Index].Value!=T.Value || !T.Value)return Close();
    if (Records[T.Index].Kind==State::Pending)return true;
    return Transition(T,State::Linked,State::Pending);
  }
  std::optional<Ticket> Take(size_t I) {
    if (!Batch || I>=Capacity || Records[I].Kind!=State::Pending)return std::nullopt;
    SetState(I,State::InFlight);return Ticket{I,Records[I].Value};
  }
  bool Complete(Ticket T,bool ObservedPublication) {
    if (!Match(T,State::InFlight))return Close();
    if (!ObservedPublication){SetState(T.Index,State::Failed);return Close();}
    Free(T.Index);return true;
  }
  bool FinishBatch() {
    if (!Batch || Closed || Count(State::Pending) || Count(State::InFlight) || Count(State::Failed))return false;
    Batch=false;return true;
  }
  bool EntryAdmissionOpen()const { return !Closed && !Batch && !Count(State::Prepared); }
  std::optional<Entry> SealEntry() {
    if (!EntryAdmissionOpen() || Next==UINT64_MAX){if(Next==UINT64_MAX)Closed=true;return std::nullopt;}
    for(size_t I=0;I<EntryCapacity;++I)if(!Entries[I]){Entries[I]=++Next;++SealedCount;return Entry{I,Entries[I]};}
    return std::nullopt;
  }
  bool MatchEntry(Entry E)const {return E.Value && E.Index<EntryCapacity && Entries[E.Index]==E.Value;}
  bool ReleaseEntry(Entry E){if(!MatchEntry(E))return Close();Entries[E.Index]=0;--SealedCount;return true;}
  bool HasSealedEntries()const{return SealedCount!=0;}
  State GetState(size_t I)const{return I<Capacity?Records[I].Kind:State::Failed;}
  uint64_t GetTicket(size_t I)const{return I<Capacity?Records[I].Value:0;}
  size_t Occupied()const{return Capacity-Count(State::Free);}
  bool Close(){Closed=true;return false;}
private:
  struct Record {uint64_t Value{};State Kind{State::Free};};
  size_t Count(State S)const{return Counts[static_cast<size_t>(S)];}
  void SetState(size_t I,State S){--Counts[static_cast<size_t>(Records[I].Kind)];Records[I].Kind=S;++Counts[static_cast<size_t>(S)];}
  void Free(size_t I){SetState(I,State::Free);Records[I].Value=0;FreeWords[I/64]|=uint64_t{1}<<(I%64);}
  bool Match(Ticket T,State S)const{return T.Value && T.Index<Capacity && Records[T.Index].Value==T.Value && Records[T.Index].Kind==S;}
  bool Transition(Ticket T,State From,State To){if(!Match(T,From))return Close();SetState(T.Index,To);return true;}
  std::array<Record,Capacity> Records{};
  std::array<uint64_t,EntryCapacity> Entries{};
  std::array<uint64_t,Capacity/64> FreeWords{};
  std::array<size_t,6> Counts{Capacity,0,0,0,0,0};
  size_t SealedCount{};
  uint64_t Next{};
  bool Closed{},Batch{};
};
using TicketLedger = BasicTicketLedger<CAPACITY>;
} // namespace FEXCore::CPU::PearJITLinks
