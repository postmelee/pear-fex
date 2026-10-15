// SPDX-License-Identifier: MIT
#pragma once
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>

// Internal diagnostic bookkeeping only. The adapter supplies a saved guest
// context at an executed instruction and validated copies; no guest pointers
// are dereferenced here. A transfer intention must never be passed as execution.
namespace PearPhase {
enum class Kind : uint32_t { Point, FunctionEntry, SceneNameEntry, SceneLoaded, ActiveScene, BeforeRet, TailTransfer, SceneUnloaded };
enum class Event : uint32_t { Point, Entry, CallerResumed, Unpaired, ThreadEnded, ModuleEnded, SceneBound, InvalidName, ModuleMapped };
enum Loss : uint32_t { Contention=1, Full=2, Threads=4, Depth=8, Invalid=16, Interrupted=32 };
struct Name {
  uint32_t Size {};
  std::array<char16_t, 48> Text {};
  bool Valid {};
};
struct Context {
  uint64_t Thread {}, Lifetime {}, Generation {}, PC {}, SP {};
  uint64_t Object {}, Arg1 {}, Value {}, ReturnPC {};
  bool ReturnReadable {};
  Name ReturnedName {};
};
struct Record {
  uint64_t Sequence {}, Thread {}, Lifetime {}, Generation {}, Invocation {};
  uint64_t PC {}, SP {}, Object {}, EntryPC {}, ReturnPC {}, EntrySP {}, Value {}, Arg1 {};
  uint32_t Marker {};
  Event Type {};
  Kind Source {};
  Name SceneName {};
};
struct Pending {
  uint64_t Invocation {}, EntryPC {}, ReturnPC {}, SP {}, Object {}, Generation {};
  uint32_t Marker {};
  Kind Source {};
};
// One attempt only: recording never waits on another thread or reentrant hook.
// Loss is sticky; a consumer may display positive hits but cannot certify a
// complete trace after any loss. The consumer must retain terminal LossFlags.
template<size_t RecordCount=4096, size_t ThreadCount=64, size_t CallDepth=16>
class Recorder {
  static_assert(RecordCount && ThreadCount && CallDepth);
  static_assert(std::atomic<uint32_t>::is_always_lock_free);
  struct Thread {
    uint64_t ID {}, Lifetime {};
    size_t Count {};
    std::array<Pending, CallDepth> Calls {};
  };
  std::atomic_flag Busy = ATOMIC_FLAG_INIT;
  std::atomic<uint32_t> Lost {};
  std::atomic<uint32_t> Active {};
  std::atomic<bool> Enabled {};
  std::array<Thread, ThreadCount> ThreadsState {};
  std::array<Record, RecordCount> Records {};
  size_t Written {}, Read {};
  uint64_t Serial {};
  struct Guard {
    Recorder& Owner;
    bool Held;
    explicit Guard(Recorder& o, bool recordLoss=true) : Owner(o), Held(!o.Busy.test_and_set(std::memory_order_acquire)) {
      if (!Held && recordLoss) o.Lost.fetch_or(Contention, std::memory_order_relaxed);
    }
    ~Guard() { if (Held) Owner.Busy.clear(std::memory_order_release); }
  };
  Thread* Find(const Context& c, bool create) {
    Thread* vacant=nullptr;
    for (auto& t: ThreadsState) {
      if (t.ID==c.Thread && t.Lifetime==c.Lifetime) return &t;
      if (!t.ID && !vacant) vacant=&t;
    }
    if (!create) return nullptr;
    if (!vacant) { Lost.fetch_or(Threads, std::memory_order_relaxed); return nullptr; }
    vacant->ID=c.Thread; vacant->Lifetime=c.Lifetime;
    return vacant;
  }
  void Add(const Context& c, Event event, Kind kind, uint32_t marker, const Pending* call=nullptr) {
    if (Written==RecordCount) { Lost.fetch_or(Full, std::memory_order_relaxed); return; }
    Record& r=Records[Written];
    r.Sequence=Written+1; r.Thread=c.Thread; r.Lifetime=c.Lifetime; r.Generation=c.Generation;
    r.PC=c.PC; r.SP=c.SP; r.Object=c.Object; r.Value=c.Value; r.Arg1=c.Arg1;
    r.Marker=marker; r.Type=event; r.Source=kind;
    if (call) {
      r.Invocation=call->Invocation; r.EntryPC=call->EntryPC;
      r.ReturnPC=call->ReturnPC; r.EntrySP=call->SP; r.Object=call->Object;
    }
    if (event==Event::SceneBound) r.SceneName=c.ReturnedName;
    ++Written;
  }
  bool Valid(const Context& c) {
    if (c.Thread && c.Lifetime && c.Generation && c.PC && c.SP) return true;
    Lost.fetch_or(Invalid, std::memory_order_relaxed); return false;
  }
public:
  // Configuration changes only before the process starts or after quiescence.
  void Enable(bool value) { Enabled.store(value, std::memory_order_release); }
  bool IsEnabled() const { return Enabled.load(std::memory_order_acquire); }
  const std::atomic<uint32_t>* ActiveAddress() const { return &Active; }
  uint32_t LossFlags() const { return Lost.load(std::memory_order_acquire); }
  void MarkLoss(uint32_t flags) { Lost.fetch_or(flags, std::memory_order_relaxed); }
  // All block-entry and call-continuation hooks call this before Marker().
  // The caller is actually executing PC, with guest SP already restored.
  void Execute(const Context& c) {
    if (!IsEnabled()) return;
    Guard g(*this); if (!g.Held || !Valid(c)) return;
    Thread* t=Find(c,false); if (!t) return;
    for (size_t i=t->Count; i>0; --i) {
      const Pending p=t->Calls[i-1];
      if (p.Generation!=c.Generation || p.ReturnPC!=c.PC || p.SP+8!=c.SP) continue;
      if (i!=t->Count) {
        Lost.fetch_or(Interrupted,std::memory_order_relaxed);
        Add(c,Event::Unpaired,p.Source,p.Marker,&p); Active.fetch_sub(t->Count,std::memory_order_relaxed); t->Count=0; return;
      }
      --t->Count; Active.fetch_sub(1,std::memory_order_relaxed);
      Add(c,Event::CallerResumed,p.Source,p.Marker,&p);
      if (p.Source==Kind::SceneNameEntry) {
        const auto& n=c.ReturnedName;
        bool valid=n.Valid && n.Size && n.Size<=n.Text.size();
        if (valid) for (size_t j=0;j<n.Size;++j) if (!n.Text[j]) valid=false;
        Add(c,valid?Event::SceneBound:Event::InvalidName,p.Source,p.Marker,&p);
      }
      // Adjacent selected tail calls share the same return slot. One arrival
      // completes that entire matched chain, but never skips a different frame.
      continue;
    }
  }
  void Marker(const Context& c, Kind kind, uint32_t marker) {
    if (!IsEnabled()) return;
    Guard g(*this); if (!g.Held || !Valid(c)) return;
    if (kind!=Kind::FunctionEntry && kind!=Kind::SceneNameEntry) {
      Add(c,Event::Point,kind,marker); return;
    }
    if (!c.ReturnReadable || !c.ReturnPC || c.SP>std::numeric_limits<uint64_t>::max()-8) {
      Lost.fetch_or(Invalid,std::memory_order_relaxed); Add(c,Event::Unpaired,kind,marker); return;
    }
    Thread* t=Find(c,true); if (!t) return;
    if (t->Count==CallDepth || Serial==std::numeric_limits<uint64_t>::max()) {
      Lost.fetch_or(Depth,std::memory_order_relaxed); return;
    }
    Pending& p=t->Calls[t->Count++]; Active.fetch_add(1,std::memory_order_relaxed);
    p={++Serial,c.PC,c.ReturnPC,c.SP,c.Object,c.Generation,marker,kind};
    Add(c,Event::Entry,kind,marker,&p);
  }
  bool WantsName(const Context& c) {
    if (!IsEnabled()) return false;
    Guard g(*this); if (!g.Held) return false;
    Thread* t=Find(c,false); if (!t || !t->Count) return false;
    for (size_t i=t->Count;i>0;--i) {
      const auto& p=t->Calls[i-1];
      if (p.Generation!=c.Generation || p.ReturnPC!=c.PC || p.SP+8!=c.SP) return false;
      if (p.Source==Kind::SceneNameEntry) return true;
    }
    return false;
  }
  // Adapter calls this at exception/unwind and thread teardown boundaries.
  void EndThread(uint64_t id, uint64_t life) {
    if (!IsEnabled()) return;
    Guard g(*this); if (!g.Held) return;
    Context c {}; c.Thread=id; c.Lifetime=life;
    Thread* t=Find(c,false); if (!t) return;
    if (t->Count) {
      Lost.fetch_or(Interrupted,std::memory_order_relaxed);
      for (size_t i=0;i<t->Count;++i) { c.Generation=t->Calls[i].Generation; Add(c,Event::ThreadEnded,t->Calls[i].Source,t->Calls[i].Marker,&t->Calls[i]); }
    }
    Active.fetch_sub(t->Count,std::memory_order_relaxed); *t={};
  }
  void BeginModule(uint64_t generation,uint64_t base,uint64_t size) {
    if (!IsEnabled()) return;
    Guard g(*this); if (!g.Held) return;
    if (!generation || !base || !size || base>UINT64_MAX-size) {
      Lost.fetch_or(Invalid,std::memory_order_relaxed); return;
    }
    Context c {};c.Generation=generation;c.PC=base;c.Value=size;
    Add(c,Event::ModuleMapped,Kind::Point,0);
  }
  void EndModule(uint64_t generation) {
    if (!IsEnabled()) return;
    Guard g(*this); if (!g.Held) return;
    Context ended {};ended.Generation=generation;Add(ended,Event::ModuleEnded,Kind::Point,0);
    for (auto& t:ThreadsState) {
      bool affected=false;
      for (size_t i=0;i<t.Count;++i) if (t.Calls[i].Generation==generation) affected=true;
      if (!affected) continue;
      Lost.fetch_or(Interrupted,std::memory_order_relaxed);
      Active.fetch_sub(t.Count,std::memory_order_relaxed); t.Count=0;
    }
  }
  // Copy one record while holding the guard; format/output after returning.
  // Storage is append-only for the bounded run, so draining never hides overflow.
  bool Take(Record& out) {
    // A reader can retry; no event is discarded when only draining contends.
    Guard g(*this,false); if (!g.Held || Read==Written) return false;
    out=Records[Read++]; return true;
  }
};
static_assert(sizeof(Recorder<>) < 2*1024*1024);
} // namespace PearPhase
