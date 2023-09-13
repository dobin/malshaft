import pyvex
import archinfo
from pyvex import IRStmt, IRSB
from typing import List

from model import *


def pyvexAnalyze(shellcode, codeVra=0x400400) -> List[BasicBlock]:
    """Returns a list of all BasicBlock from shellcode"""
    bb: List[BasicBlock] = []
    n = 0
    while n < len(shellcode):
        # lift gives us a BB each time
        irsb = pyvex.lift(shellcode, codeVra+n, archinfo.ArchAMD64(), bytes_offset=n)
        bb.append(BasicBlock(irsb))
        n += irsb.size
    return bb


def augmentVex(peFile: PeFile):
    resolveMethodBbNext(peFile)
    resolveMethodBBOutput(peFile)


def resolveMethodBbNext(peFile: PeFile):
    """Resolve the basicblock's next ptr (instead of a VRA) for each function"""
    for method in peFile.methods:
        # resolve next ptr for each bb (from address to bb)
        for bb in method.vexBB:
            n = str(bb.irsb.next)  # hack
            if n.startswith("0x"):
                nextAddr = int(n, 16)
                bb.next = "0x{:x}".format(nextAddr)

                # search
                for m in peFile.methods:
                    for b in m.vexBB:
                        if b.irsb.addr == nextAddr:
                            bb.next = b
                            break
                for s in peFile.symbols:
                    if s.offset == nextAddr:
                        bb.next = s.value
            elif n.startswith("t"):
                bb.next = "ret"
            else:
                bb.next = n


def resolveMethodBBOutput(peFile: PeFile):
    """Resolve the hashable representation of each bb of each function"""
    for method in peFile.methods:
        # create BB output
        vexStr = ""
        for bb in method.vexBB:
            vexStr += "BB Addr: 0x{:x}\n".format(bb.irsb.addr)

            stmt: IRStmt
            for stmt in bb.irsb.statements:
                t = type(stmt).__name__

                if t == "IMark":
                    # ------ IMark(0x402570, 1, 0) ------
                    # address of BB
                    # no need
                    pass
                elif t == "AbiHint":
                    # ret:  ====== AbiHint(0xt6, 128, t4) ======
                    # call: ====== AbiHint(0xt10, 128, 0x0000000000401190) ======
                    # same as bb.irsb.next mostly
                    # no need
                    pass
                else:
                    vexStr += "  {}\n".format(stmt)

            vexStr += "  -> {}\n".format(bb.next)
            vexStr += "\n"

        method.vexStr = vexStr




