# Remill

https://github.com/lifting-bits/remill/blob/master/docs/LIFE_OF_AN_INSTRUCTION.md

## One

;; mov ebx, dword ptr [esp + 8]
(X86 804809e 4 (BYTES 8b 5c 24 08)
  MOV_GPRv_MEMv_32
    (WRITE_OP (REG_32 EBX))
    (READ_OP  (DWORD_PTR (ADD (REG_32 SS_BASE)
                              (REG_32 ESP)
                              (SIGNED_IMM_32 0x8)))))


## Two

Memory *__remill_basic_block_804b7a3(State *state, addr_t pc, Memory *memory) {
  auto &EIP = state.gpr.rip.dword;
  auto &EAX = state.gpr.rax.dword;
  auto &EBX = state.gpr.rbx.dword;
  auto &ESP = state.gpr.rsp.dword;

  // mov    eax, 0x1
  EAX = 1;

  // push   ebx
  ESP -= 4;
  memory = __remill_write_memory_32(memory, ESP, EBX);

  // mov    ebx, dword [esp+0x8]
  EBX = __remill_read_memory_32(memory, ESP + 0x8);

  // int    0x80
  state.hyper_call = AsyncHyperCall::kX86IntN;
  state.interrupt_vector = 0x80;

  EIP = pc + 12;

  return __remill_async_hyper_call(state, EIP, memory)
}