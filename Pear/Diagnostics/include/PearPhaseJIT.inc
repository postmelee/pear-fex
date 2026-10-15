// SPDX-License-Identifier: MIT
// Included in the existing Arm64JITCore namespace. No CpuStateFrame ABI change.
#ifdef PEAR_PHASE_OBSERVE
extern "C" bool PearPhaseEnabled();
extern "C" bool PearPhaseSelected(uint64_t);
extern "C" const void* PearPhaseActiveAddress();
extern "C" void PearPhaseExecuted(FEXCore::Core::CpuStateFrame*, uint64_t, uint64_t);
void Arm64JITCore::EmitPearPhase(uint64_t PC, bool Marker) {
  if (!PearPhaseEnabled()) return;
  ARMEmitter::ForwardLabel Skip;
  if (!Marker) {
    LoadConstant(ARMEmitter::Size::i64Bit, TMP1, reinterpret_cast<uintptr_t>(PearPhaseActiveAddress()));
    ldr(TMP1.W(), TMP1, 0);
    (void)cbz(ARMEmitter::Size::i32Bit, TMP1, &Skip);
  }
  // Print's existing static/dynamic save path includes NZCV, PF/AF and SIMD.
  // Preserve the exact FPCR/FPSR additionally across the native diagnostic call.
  constexpr auto FPSR=static_cast<ARMEmitter::SystemRegister>(ARMEmitter::GenSystemReg<3,3,4,4,1>);
  mrs(TMP1, ARMEmitter::SystemRegister::FPCR);
  mrs(TMP2, FPSR);
  stp<ARMEmitter::IndexType::PRE>(TMP1, TMP2, ARMEmitter::Reg::rsp, -16);
  PushDynamicRegs(TMP1);
  SpillStaticRegs(TMP1);
  mov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r0, STATE.R());
  LoadConstant(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r1, PC);
  LoadConstant(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r2, Marker ? 1 : 0);
  LoadConstant(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r3, reinterpret_cast<uintptr_t>(PearPhaseExecuted));
  blr(ARMEmitter::Reg::r3);
  FillStaticRegs();
  PopDynamicRegs();
  ldp<ARMEmitter::IndexType::POST>(TMP1, TMP2, ARMEmitter::Reg::rsp, 16);
  msr(ARMEmitter::SystemRegister::FPCR, TMP1);
  msr(FPSR, TMP2);
  (void)Bind(&Skip);
}
#endif
