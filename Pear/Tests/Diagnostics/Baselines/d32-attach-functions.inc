static bool SameBinding(const Binding& A, const Binding& B) {
  return A.TEB == B.TEB && A.NativeThread == B.NativeThread && A.SourceState == B.SourceState &&
         A.SourceContext == B.SourceContext && A.SourceKind == B.SourceKind &&
         A.Executor == B.Executor && A.Role == B.Role && A.Unresolved == B.Unresolved && A.LifetimeSerial == B.LifetimeSerial;
}
static bool ThreadFieldsMatch(const FEXCore::Context::Context* ActualContext,
                             const FEXCore::Core::InternalThreadState* Thread) {
  // This call is made while the real newly allocated source object is alive.
  // CurrentBinding and destructor cleanup never dereference this identity.
  return ActualContext && Thread && Thread->CTX == ActualContext && Thread->CurrentFrame &&
         Thread->CurrentFrame == &Thread->BaseFrameState && Thread->CurrentFrame->Thread == Thread;
}
static bool HasUnreleasedOwner(const Binding& B) {
  return B.Executor || B.Unresolved || B.Pending || B.Capturing || B.LifetimeHolds || (B.Active.Kind != LeaseKind::None);
}

static Result BindActual(const FEXCore::Context::Context* Context, const void* SourceState, Binding::Kind Kind) {
  const auto Admission = NewAdmission();
  if (!Admission) return Admission;
  if (!Context || !SourceState || !Configured.load(std::memory_order_acquire) || !BridgeDirect || !OwnerPID) return Refuse();
  const auto TEB = GetCurrentTEB();
  const auto ID = reinterpret_cast<uintptr_t>(TEB->ClientId.UniqueThread);
  if (!ID) return Refuse();
  RegistryGuard Guard;
  auto* Life = ContextRecord(Context);
  if (!Life || Life->Closing || Life->DeleteSealed || Life->Retained) return Refuse();
  Binding* Empty {};
  for (auto& B : Bindings) {
    if (B.TEB == TEB && B.NativeThread == ID) {
      if (B.Pending || B.Capturing || B.Unresolved || B.LifetimeClosing || B.SourceKind != Kind ||
          B.SourceContext != Context || B.SourceState != SourceState) return Refuse(PEAR_FEX_STALE_IDENTITY);
      return Refuse(PEAR_FEX_OK);
    }
    if (!B.TEB && !Empty) Empty = &B;
  }
  if (!Empty || NextLifetimeSerial == UINT64_MAX) return Refuse(PEAR_FEX_CAPACITY);
  *Empty = {};
  Empty->TEB = TEB; Empty->NativeThread = ID; Empty->SourceState = SourceState;
  Empty->SourceContext = Context; Empty->SourceKind = Kind; Empty->LifetimeSerial = ++NextLifetimeSerial;
  return Refuse(PEAR_FEX_OK);
}static Result RegisterActualExecutor(uint32_t SourceRole, bool CleanupOnly) {
  if (!CleanupOnly) {
    const auto Admission=NewAdmission(); if (!Admission) return Admission;
  }
  Binding Snapshot;
  {
    RegistryGuard Guard;
    auto* B = CurrentBinding();
    auto* C=B ? ContextRecord(B->SourceContext) : nullptr;
    if (!B || !C || C->DeleteSealed || C->Retained || C->DestroyedBacking || B->LifetimeClosing ||
        B->Executor || B->Pending || B->Capturing || B->Unresolved || SourceRole!=CompiledSourceRole() ||
        (CleanupOnly ? (!B->CleanupOnly || B->SourceKind!=Binding::Kind::Bootstrap || !C->Closing || C->Holds ||
          C->CreationTEB!=B->TEB || C->CreationNativeThread!=B->NativeThread) : (C->Closing || B->CleanupOnly))) return Refuse();
    B->Pending = true; B->Transition=PendingTransition::Unknown; Snapshot = *B;
  }
  auto Q = Request(PEAR_FEX_EXECUTOR_REGISTER); Q.ec_role = SourceRole;
  pear_fex_memory_response R {};
  InvocationFacts Facts;
  auto Outcome = Invoke(Q, R, &Facts);
  if (Outcome && (!R.executor_id || R.flags != PEAR_FEX_NATIVE_IDLE || !NoTargetFacts(R)))
    Outcome = ResponseShapeFailure(Q.opcode);
  const bool Uncertain = !Outcome && Facts.BridgeCalled && !Facts.ValidatedRefusal;
  Result Cleanup;
  InvocationFacts CleanupFacts;
  if (Uncertain) {
    Retirement::PoisonSourceAdmission(Outcome);
    // Only the observed called-success identity can be used for this cleanup.
    // A zero/malformed ID or failure response never invents an unregister call.
    if (Facts.CleanupCandidate) Cleanup = CheckedUnregister(Facts.CleanupCandidate, &CleanupFacts);
  }
  {
    RegistryGuard Guard;
    auto* B = CurrentBinding();
    if (!B || !SameBinding(*B, Snapshot) || !B->Pending) {
      const auto Lost = Outcome ? Refuse(PEAR_FEX_STALE_IDENTITY) : Outcome;
      Retirement::PoisonSourceAdmission(Lost);
      return Lost;
    }
    B->Pending = false; B->Transition=PendingTransition::Unknown;
    if (Outcome) {
      B->Executor = R.executor_id; B->Role = SourceRole;
      B->OriginalFailure = Refuse(PEAR_FEX_OK); B->CleanupOutcome = {}; B->CleanupAttempted = false;
    }
    else {
      B->OriginalFailure = Outcome; B->CleanupOutcome = Cleanup;
      B->CleanupAttempted = CleanupFacts.BridgeCalled;
      B->Unresolved = Uncertain && !Cleanup;
      B->Executor = B->Unresolved ? Facts.CleanupCandidate : 0;
      B->Role = B->Unresolved ? SourceRole : 0;
    }
  }
  return Outcome;
}
Result RegisterExecutor(uint32_t SourceRole) { return RegisterActualExecutor(SourceRole,false); }
Result SourceLifecycle::AttachAllocatedThread(const FEXCore::Context::Context* Context,
                            FEXCore::Core::InternalThreadState* Thread, uint32_t SourceRole) {
  if (!ThreadFieldsMatch(Context, Thread) || SourceRole != CompiledSourceRole())
    return Refuse(PEAR_FEX_INVALID_REQUEST);
  const auto Admission = NewAdmission();
  if (!Admission) return Admission;
  Binding Existing;
  bool SameThread {};
  {
    RegistryGuard Guard;
    auto* B = CurrentBinding();
    if (B) {
      if (B->SourceContext != Context || B->Pending || B->Capturing || (B->Active.Kind != LeaseKind::None) || B->Unresolved)
        return B->Unresolved && !B->OriginalFailure ? B->OriginalFailure : Refuse(PEAR_FEX_STALE_IDENTITY);
      SameThread = B->SourceKind == Binding::Kind::Thread && B->SourceState == Thread;
      if (!SameThread && B->SourceKind != Binding::Kind::Bootstrap) return Refuse(PEAR_FEX_STALE_IDENTITY);
      B->AttachAttempt = Thread;
      Existing = *B;
      if (SameThread && B->Executor) { B->Pending = true; B->Transition=PendingTransition::Unknown; }
      // A clean bootstrap or earlier confirmed registration refusal has no
      // owner executor. Erase only this exact live matching identity.
      if (!B->Executor && !HasUnreleasedOwner(*B) && B->SourceKind == Binding::Kind::Bootstrap) *B = {};
    }
  }
  if (SameThread && Existing.Executor) {
    if (Existing.Role != SourceRole) {
      const auto BadRole = Refuse(PEAR_FEX_STALE_IDENTITY);
      Retirement::PoisonSourceAdmission(BadRole);
      return FinishTransition(Existing, BadRole);
    }
    // Idempotence requires a new actual native-idle owner observation. The NX
    // lock was released before the call; no unregistered ID is reused.
    const auto Idle = ObserveRegisteredIdle(Existing);
    const auto Finished = FinishTransition(Existing, Idle);
    if (!Finished) {
      RegistryGuard Guard;
      auto* B = CurrentBinding();
      if (B && SameBinding(*B, Existing)) {
        B->OriginalFailure = Finished; B->CleanupOutcome = {}; B->CleanupAttempted = false;
      }
      Retirement::PoisonSourceAdmission(Finished);
    }
    return Finished;
  }
  if (Existing.Executor) {
    // Preserve the live bootstrap Context on any refusal/unknown cleanup.
    const auto Unregistered = UnregisterExecutor();
    if (!Unregistered) return Unregistered;
    // Clear only this exact known-unregistered bootstrap for the source-owned
    // transfer. A Thread tombstone is never discarded by Attach or CanRelease.
    RegistryGuard Guard;
    auto* B=CurrentBinding(); auto* C=ContextRecord(Context);
    if (!B || !C || C->Closing || C->DeleteSealed || C->Retained || B->SourceKind != Binding::Kind::Bootstrap ||
        B->SourceContext != Context || B->AttachAttempt != Thread || HasUnreleasedOwner(*B)) return Refuse(PEAR_FEX_STALE_IDENTITY);
    *B={};
  }
  const auto Bound = BindActual(Context, Thread, Binding::Kind::Thread);
  if (!Bound) return Bound;
  return RegisterExecutor(SourceRole);
}