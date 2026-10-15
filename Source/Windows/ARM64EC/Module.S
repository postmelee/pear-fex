.text
.balign 16

#ifdef PEAR_FEX_MEMORY_OWNER
.macro PEAR_EC_GATE mode
  mov x16, sp
  and x17, x16, #-16
  mov sp, x17
  sub sp, sp, #800
  stp x0, x1, [sp, #0]
  stp x2, x3, [sp, #16]
  stp x4, x5, [sp, #32]
  stp x6, x7, [sp, #48]
  stp x8, x9, [sp, #64]
  stp x10, x11, [sp, #80]
  stp x12, x13, [sp, #96]
  stp x14, x15, [sp, #112]
  stp x18, x19, [sp, #128]
  stp x20, x21, [sp, #144]
  stp x22, x23, [sp, #160]
  stp x24, x25, [sp, #176]
  stp x26, x27, [sp, #192]
  stp x28, x29, [sp, #208]
  stp x30, x16, [sp, #224]
  mrs x16, nzcv
  mrs x17, fpcr
  stp x16, x17, [sp, #240]
  and x17, x17, #~6
  msr fpcr, x17
  mrs x16, fpsr
  str x16, [sp, #256]
  stp q0, q1, [sp, #272]
  stp q2, q3, [sp, #304]
  stp q4, q5, [sp, #336]
  stp q6, q7, [sp, #368]
  stp q8, q9, [sp, #400]
  stp q10, q11, [sp, #432]
  stp q12, q13, [sp, #464]
  stp q14, q15, [sp, #496]
  stp q16, q17, [sp, #528]
  stp q18, q19, [sp, #560]
  stp q20, q21, [sp, #592]
  stp q22, q23, [sp, #624]
  stp q24, q25, [sp, #656]
  stp q26, q27, [sp, #688]
  stp q28, q29, [sp, #720]
  stp q30, q31, [sp, #752]
  mov w0, \mode
  bl "#PearECGate"
  ldp q0, q1, [sp, #272]
  ldp q2, q3, [sp, #304]
  ldp q4, q5, [sp, #336]
  ldp q6, q7, [sp, #368]
  ldp q8, q9, [sp, #400]
  ldp q10, q11, [sp, #432]
  ldp q12, q13, [sp, #464]
  ldp q14, q15, [sp, #496]
  ldp q16, q17, [sp, #528]
  ldp q18, q19, [sp, #560]
  ldp q20, q21, [sp, #592]
  ldp q22, q23, [sp, #624]
  ldp q24, q25, [sp, #656]
  ldp q26, q27, [sp, #688]
  ldp q28, q29, [sp, #720]
  ldp q30, q31, [sp, #752]
  ldr x16, [sp, #256]
  msr fpsr, x16
  ldp x16, x17, [sp, #240]
  msr nzcv, x16
  msr fpcr, x17
  ldp x0, x1, [sp, #0]
  ldp x2, x3, [sp, #16]
  ldp x4, x5, [sp, #32]
  ldp x6, x7, [sp, #48]
  ldp x8, x9, [sp, #64]
  ldp x10, x11, [sp, #80]
  ldp x12, x13, [sp, #96]
  ldp x14, x15, [sp, #112]
  ldp x18, x19, [sp, #128]
  ldp x20, x21, [sp, #144]
  ldp x22, x23, [sp, #160]
  ldp x24, x25, [sp, #176]
  ldp x26, x27, [sp, #192]
  ldp x28, x29, [sp, #208]
  ldp x30, x16, [sp, #224]
  mov sp, x16
.endm
#endif

  // __os_arm64x_x64_jump in ARM64EC docs
  // Expects target code address in x9
.globl DispatchJump
DispatchJump:
  str lr, [sp, #-8]! // Push return address to stack, this will be popped by the x86 RET instr.
  b check_target_ec

  // __os_arm64x_dispatch_ret in ARM64EC docs
  // Expects target code address in lr
.globl RetToEntryThunk
RetToEntryThunk:
  mov x9, lr

check_target_ec:
  // Check if target is in fact x86 code
  ldr x16, [x18, #0x60] // TEB->PEB
  ldr x16, [x16, #0x368] // PEB->EcCodeBitMap
  lsr x17, x9, #18
  ldr x16, [x16, x17, lsl #3]
  lsr x17, x9, #12
  lsr x16, x16, x17
  tbnz x16, #0, ExitFunctionEC
  b enter_jit

  // __os_arm64x_dispatch_call_no_redirect in ARM64EC docs
  // Expects target code address in x9, and to be called using a 'blr x16' instruction.
.globl ExitToX64
ExitToX64:
  str lr, [sp, #-8]! // Push return address to stack, this will be popped by the x86 RET instr.

enter_jit:
#ifdef PEAR_FEX_MEMORY_OWNER
  PEAR_EC_GATE 0
#endif
  ldr x17, [x18, #0x1788] // TEB->ChpeV2CpuAreaInfo
  mov w16, #1
  strb w16, [x17, #0x0] // ChpeV2CpuAreaInfo->InSimulation
  ldr x16, [x17, #0x40] // ChpeV2CpuAreaInfo->EmulatorData[2] - DispatcherLoopTopEnterEC
  br x16 // DispatcherLoopTopEnterEC(RIP:x9, CPUArea:x17)

  // Invoked by KiUserEmulationDispatcher after e.g. an NtContinue to x86 code
.global BeginSimulation
BeginSimulation:
  ldr x17, [x18, #0x1788] // TEB->ChpeV2CpuAreaInfo
  ldr x16, [x17, #0x8] // ChpeV2CpuAreaInfo->EmulatorStackBase
  mov sp, x16
  ldr x0, [x17, #0x18] // ChpeV2CpuAreaInfo->ContextAmd64
  bl "#SyncThreadContext"
#ifdef PEAR_FEX_MEMORY_OWNER
  PEAR_EC_GATE 1
#endif
  ldr x17, [x18, #0x1788] // TEB->ChpeV2CpuAreaInfo
  ldr x16, [x17, #0x48] // ChpeV2CpuAreaInfo->EmulatorData[3] - DispatcherLoopTopEnterECFillSRA
  mov x11, #0 // Zero ENTRY_FILL_SRA_SINGLE_INST_REG to avoid single step
  br x16 // DispatcherLoopTopEnterECFillSRA(SingleInst:x10, CPUArea:x17)

  // Called into by FEXCore
  // Expects the target code address in x9
.global ExitFunctionEC
ExitFunctionEC:
#ifdef PEAR_FEX_MEMORY_OWNER
  PEAR_EC_GATE 2
#endif
  // Clear any the AFP NEP and AH bits in FPCR as native code won't expect their behaviour.
  mrs x17, fpcr
  and x17, x17, #~6 // NEP + AH
  msr fpcr, x17
  ldr x17, [x18, #0x1788] // TEB->ChpeV2CpuAreaInfo
  strb wzr, [x17, #0x0] // ChpeV2CpuAreaInfo->InSimulation
  ldr x17, [x17, #0x20] // ChpeV2CpuAreaInfo->SuspendDoorbell
  ldr w17, [x17]
  cbnz w17, ExitFunctionSuspendPoint

.global ExitFunctionSuspendResumePoint
ExitFunctionSuspendResumePoint:
  // Either return to an exit thunk (return to ARM64EC function) or call an entry thunk (call to ARM64EC function).
  // It is assumed that a 'blr x16' instruction is only ever used to call into x86 code from an exit thunk, and that all
  // exported ARM64EC functions have a 4-byte offset to their entry thunk immediately before their first instruction.
  mov x17, x9
  mov w16, #0x200
  movk w16, #0xd63f, lsl 16 // blr x16
  ldursw x23, [x17, #-0x4] // Load either the entry thunk offset or the calling instruction.
  cmp w23, w16
  beq ret_sp_aligned

  and x23, x23, #-0x4
  add x17, x17, x23 // Resolve entry thunk address.

  mov x4, sp
  tbz x4, #3, ret_sp_misaligned
  ldr lr, [x4], #0x8 // Pop the return address into lr.
  mov sp, x4

ret_sp_aligned:
  br x17

ret_sp_misaligned:
  // In the case of the x64 caller leaving sp only 8-byte aligned, leave the return address on the stack to keep 16-byte
  // alignment and have the callee return to an x86 ret instruction. FEX can then return to the actual caller keeping
  // the misaligned RSP.
  adrp lr, X64ReturnInstr
  ldr lr, [lr, #:lo12:X64ReturnInstr]
  br x17

.global ExitFunctionSuspendPoint
ExitFunctionSuspendPoint:
  brk #0xCAFE
  // Resume will jump back to `ExitFunctionSuspendResumePoint`

  // Makes a wrapper for calling a system call directly, skipping the usual ntdll thunks
#define HASH #
#define DIRECT_SYSCALL_WRAPPER(Name, WineIdName, WindowsId) \
  .global Name; \
  Name:; \
    adrp x16, WineSyscallDispatcher; \
    ldr x16, [x16, HASH:lo12:WineSyscallDispatcher]; \
    cbz x16, 1f; \
    mov x9, x30; \
    adrp x8, WineIdName; \
    ldr x8, [x8, HASH:lo12:WineIdName]; \
    blr x16; \
    ret; \
  1:; \
    svc HASH WindowsId; \
    ret

  // Allows for continuing from a full native context, as the NTDLL NtContinue export takes in an x64 context with EC and
  // the conversion to that loses the ARM64EC ABI-disallowed registers that FEX uses.
DIRECT_SYSCALL_WRAPPER("#NtContinueNative", WineNtContinueSyscallId, 0x43)
DIRECT_SYSCALL_WRAPPER("#NtRaiseExceptionNative", WineNtRaiseExceptionSyscallId, 0x174)

  // Both of these are wrapped as FEX needs them to setup its call checker at startup time and their NTDLL thunks could
  // already be patched by then (and because the call checker isn't installed, their patched x86 versions would be invoked
  // when called by FEX).
DIRECT_SYSCALL_WRAPPER("#NtAllocateVirtualMemoryNative", WineNtAllocateVirtualMemorySyscallId, 0x18)
DIRECT_SYSCALL_WRAPPER("#NtProtectVirtualMemoryNative", WineNtProtectVirtualMemorySyscallId, 0x50)

  // A replacement for the standard ARM64EC call checker that ignores any FFS patches and always redirects to a function's
  // native implementation. As the only library FEX calls into is NTDLL, this is done using a LUT generated at init time.
  // Expects the FFS address in x11, exit thunk address in x10 (unused) and it's own address in x9. Return address is in x11.
.global "CheckCall"
"CheckCall":
  adrp x9, NtDllBase
  ldr x9, [x9, #:lo12:NtDllBase]
  subs x16, x11, x9
  b.lo end
  adrp x17, NtDllRedirectionLUTSize
  ldr x17, [x17, #:lo12:NtDllRedirectionLUTSize]
  cmp x16, x17
  b.hi end
  adrp x17, NtDllRedirectionLUT
  ldr x17, [x17, #:lo12:NtDllRedirectionLUT]
  ldr w11, [x17, x16, lsl #2]
  add x11, x11, x9
end:
  ret

  // Expects target address in x0, and the SP to set in x1
.global "#JumpSetStack"
"#JumpSetStack":
  mov sp, x1
  br x0
