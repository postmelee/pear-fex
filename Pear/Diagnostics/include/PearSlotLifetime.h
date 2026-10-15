// SPDX-FileCopyrightText: 2026 Pear contributors
// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
namespace PearSlot {
enum class Stage : uint32_t { ThreadTerm=1, Destroy=2, Unregister=3, BridgeUnregister=4 };
// Opaque identities only; observation never acquires a source lifetime hold.
struct Row {
  uint64_t Context {}, Source {}, Serial {}, Executor {};
  uint32_t Holds {}, Flags {}, Snapshot {}; // 0 absent, 1 copied, 2 lock unavailable
};
struct Event {
  uint64_t Call {}, Context {}, Source {}, Serial {};
  Row Current {};
  uint32_t Stage {}, Side {}, Kind {}, Status {}, Domain {};
  int32_t Code {};
  uint32_t Returned {}, Destroyed {}, Freed {}, BridgeCalled {}, Validated {};
};
uint64_t Begin();
Row Snapshot(uint64_t context,uint64_t source);
void Emit(const Event& event);
class Scope {
  Event E {};
public:
  Scope(Stage stage,const void* context=nullptr,const void* source=nullptr) {
    E.Call=Begin(); if (!E.Call) return;
    E.Stage=static_cast<uint32_t>(stage); E.Side=1;
    E.Context=reinterpret_cast<uint64_t>(context); E.Source=reinterpret_cast<uint64_t>(source);
    E.Current=Snapshot(E.Context,E.Source);
    if (E.Current.Snapshot==1) {
      E.Context=E.Current.Context; E.Source=E.Current.Source; E.Serial=E.Current.Serial;
    }
    Emit(E);
  }
  Scope(const Scope&)=delete;
  Scope& operator=(const Scope&)=delete;
  // Explicitly called after the original callee/body returns and its local
  // guards unwind. Absence of this event is unknown, never inferred success.
  void Return(uint32_t kind,uint32_t status,uint32_t domain,int32_t code,
              bool returned=false,bool destroyed=false,bool freed=false,
              bool bridgeCalled=false,bool validated=false) {
    if (!E.Call) return;
    E.Side=2; E.Kind=kind; E.Status=status; E.Domain=domain; E.Code=code;
    E.Returned=returned; E.Destroyed=destroyed; E.Freed=freed;
    E.BridgeCalled=bridgeCalled; E.Validated=validated;
    E.Current=Snapshot(E.Context,E.Source); Emit(E); E.Call=0;
  }
};
static_assert(sizeof(Event)<=160);
}
