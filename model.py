from enum import Enum
from typing import List
from pyvex import IRStmt, IRSB
import ssdeep


class NextType(Enum):
    BasicBlock = 0
    Addr = 1

    Func = 2
    Ret = 3


class Next():
    """Where a basic block jumps next, in detail"""
    def __init__(self):
        self.type: NextType = None
        
        self.basicblock = None
        self.addr = None
        
        self.func = None
        self.ret = None


class BasicBlock():
    """Contains the basic block IRSB (Intermediate Representation Super-Block) and its data"""
    def __init__(self, irsb: IRSB):
        self.irsb = irsb
        self.hash = None
        self.instr: List[str] = []
        self.next: BasicBlock = None


    def __str__(self):
        return "BasicBlock @0x{:x}".format(self.irsb.addr)


class Symbol():
    """An vra_addr->str relationship, mostly for imported functions to resolve basicblock's next"""
    def __init__(self, offset, value):
        self.offset = offset
        self.value = value


class Method():
    """A method of the binary, its basic blocks, data and support data"""
    def __init__(self):
        self.offset = None
        self.size = None
        self.rva = None
        self.name = None
        self.disasmUi = None
        self.disasmRaw = None
        self.data = None
        self.callrefs = None

        # the LLVM bitcode (unused)
        self.llvmBitcode = None

        # the VEX data
        self.vexBB: List[BasicBlock] = []
        # the VEX data string representation
        self.vexStr: str = ""
        

    def fuzzyHash(self):
        return ssdeep.hash(self.data)
    

class PeFile():
    """Main representation of an exe file with all data we have and need"""
    def __init__(self, methods: List[Method], symbols: List[Symbol], sections = []):
        self.methods: List[Method] = methods
        self.symbols: List[Symbol] = symbols
        self.sections = sections
