# How It Works

1) Find all functions
2) Lift functions to VEX basic blocks
3) Resolve basic blocks data
4) Translate basic block data into a hashable value
5) use that value as a hash of this bb


```
Function: RVA: 0x4014e0 FileOffset:2784: dbg.mainCRTStartup ()

Disassembly UI:
            ;-- entry0:
            ;-- mainCRTStartup:
            ;-- rip:
┌ 29: dbg.mainCRTStartup ();
│           0x004014e0      4883ec28       sub rsp, 0x28               ; crtexe.c:206:0 ; int mainCRTStartup();
│           0x004014e4      488b05258300.  mov rax, qword [0x00409810] ; crtexe.c:207:0 ; [0x409810:8]=0x40c0b0
│           0x004014eb      c70000000000   mov dword [rax], 0
│           0x004014f1      e89afcffff     call dbg.__tmainCRTStartup  ; crtexe.c:212:0
│           0x004014f6      90             nop                         ; crtexe.c:214:0
│           0x004014f7      90             nop
│           0x004014f8      4883c428       add rsp, 0x28               ; crtexe.c:222:0
└           0x004014fc      c3             ret


Disassembly Raw:
subq $0x28, %rsp
movq 0x8325(%rip), %rax
movl $0, (%rax)
callq 0x401190
nop
nop
addq $0x28, %rsp
retq


Hexdump:
00000000: 48 83 EC 28 48 8B 05 25  83 00 00 C7 00 00 00 00  H..(H..%........
00000010: 00 E8 9A FC FF FF 90 90  48 83 C4 28 C3           ........H..(.

Bitcode:
None

Callrefs:
  401190 dbg.__tmainCRTStartup

VEX Str:
BB Addr: 0x4014e0
  t2 = GET:I64(offset=48)
  t0 = Sub64(t2,0x0000000000000028)
  PUT(offset=144) = 0x0000000000000008
  PUT(offset=152) = t2
  PUT(offset=160) = 0x0000000000000028
  PUT(offset=48) = t0
  PUT(offset=184) = 0x00000000004014e4
  t7 = LDle:I64(0x0000000000409810)
  PUT(offset=16) = t7
  PUT(offset=184) = 0x00000000004014eb
  STle(t7) = 0x00000000
  PUT(offset=184) = 0x00000000004014f1
  t8 = Sub64(t0,0x0000000000000008)
  PUT(offset=48) = t8
  STle(t8) = 0x00000000004014f6
  t10 = Sub64(t8,0x0000000000000080)
  -> dbg.__tmainCRTStartup

BB Addr: 0x4014f6
  t2 = GET:I64(offset=48)
  t0 = Add64(t2,0x0000000000000028)
  PUT(offset=144) = 0x0000000000000004
  PUT(offset=152) = t2
  PUT(offset=160) = 0x0000000000000028
  PUT(offset=48) = t0
  PUT(offset=184) = 0x00000000004014fc
  t4 = LDle:I64(t0)
  t5 = Add64(t0,0x0000000000000008)
  PUT(offset=48) = t5
  t6 = Sub64(t5,0x0000000000000080)
  -> ret
```