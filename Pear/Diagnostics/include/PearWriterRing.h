// SPDX-License-Identifier: MIT
#pragma once
#include <atomic>
#include <cstddef>
#include <cstdint>
// Diagnostic values only. No guest pointers are dereferenced or retained as owners.
struct PearWriterRecord {
  uint64_t sequence{},pid{},executor{},thread{},life{},operation{},source{};
  uint64_t owner{},state{},allocation{},generation{},extent{},size{},base{},aclass{},role{};
  uint64_t offset{},bytes{},store_mask{},changed_mask{},before_epoch{},write_epoch{},turn{};
  uint64_t original0{},original1{},original2{},next0{},next1{},next2{};
  uint64_t stores_done{},terminal{},publish_success{},source_updated{},status{},domain{},code{};
};
struct PearWriterCut { uint64_t seen{},sequence{},lost{}; };
struct PearWriterBatch {
  uint64_t seen{},first{},last{},lost{},count{};
  PearWriterRecord rows[64]{};
};
class PearWriterRecorder {
public:
  static constexpr size_t Capacity=64;
  void Lose(){Lost.store(true,std::memory_order_relaxed);}
  uint64_t Begin(PearWriterRecord record) {
    Guard lock{*this};if(!lock.owned)return 0;
    if(Next==UINT64_MAX){Lose();return 0;}
    const auto id=++Next;auto& row=Rows[(id-1)%Capacity];
    if(row.sequence && !row.terminal)Lose();
    record.sequence=id;record.operation=id;row=record;++Open;return id;
  }
  void Finish(uint64_t id,bool stores,uint64_t status,uint64_t domain,uint64_t code,bool published,bool updated) {
    if(!id)return;
    Guard lock{*this};if(!lock.owned)return;
    auto& row=Rows[(id-1)%Capacity];
    if(row.sequence!=id || row.terminal || !Open){Lose();return;}
    row.stores_done=stores;row.status=status;row.domain=domain;row.code=code;
    row.publish_success=published;row.source_updated=updated;row.terminal=1;--Open;
    if(!stores || !published || !updated || status)Lose();
  }
  PearWriterCut Cut() {
    Guard lock{*this};if(!lock.owned)return {};
    if(Open){Lose();return {0,Next,1};}
    return {1,Next,static_cast<uint64_t>(Lost.load(std::memory_order_relaxed))};
  }
  bool Snapshot(PearWriterBatch& out) {
    Guard lock{*this};if(!lock.owned){out={};out.lost=1;return false;}
    out={};out.seen=1;out.last=Next;out.count=Next<Capacity?Next:Capacity;
    out.first=out.count?Next-out.count+1:1;
    out.lost=Lost.load(std::memory_order_relaxed)||Open;
    for(size_t i=0;i<out.count;++i)out.rows[i]=Rows[(out.first+i-1)%Capacity];
    return true;
  }
private:
  struct Guard {
    PearWriterRecorder& ring;bool owned{};
    explicit Guard(PearWriterRecorder& r):ring(r){
      bool expected=false;
      // One weak CAS only: spurious failure is conservative diagnostic loss.
      owned=ring.Busy.compare_exchange_weak(expected,true,std::memory_order_acquire);
      if(!owned)ring.Lose();
    }
    ~Guard(){if(owned)ring.Busy.store(false,std::memory_order_release);}
    Guard(const Guard&)=delete;Guard& operator=(const Guard&)=delete;
  };
  std::atomic<bool> Busy{},Lost{};
  uint64_t Next{},Open{};
  PearWriterRecord Rows[Capacity]{};
  friend struct PearWriterRecorderProbe;
};
static_assert(std::atomic<bool>::is_always_lock_free);
static_assert(sizeof(PearWriterRecorder)<=24576);
static_assert(sizeof(PearWriterBatch)<=24576);
