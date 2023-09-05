import r2pipe
import json
import hexdump
import ssdeep
import os
import sys


class Method():
    def __init__(self):
        self.offset = None
        self.rva = None
        self.name = None
        self.disasmUi = None
        self.disasmRaw = None
        self.data = None
        self.llvmBitcode = None
        

    def fuzzyHash(self):
        pass


def convertRemill(s):
    p = False
    for line in s.split('\n'):
        #if line.endswith("{"):
        #    print("AAA")
        #if line.endswith("}"):
        #    print("BBB")
        if '@sub_0' in line:
            p = True
        if line == ("}"):
            p = False

        if p:
            l = line
            l = l.replace(', align 8', '')
            l = l.replace(', align 1', '')
            print(l)


def analyzer(filepath):
    r2 = r2pipe.open(filepath)
    r2.cmd("aaa")

    # sections
    sectionsStr = r2.cmd("iSj")
    sections = json.loads(sectionsStr)
    for section in sections:
        # {'name': '.text', 'size': 27648, 'vsize': 28672, 
        #  'perm': '-r-x', 'paddr': 1536, 'vaddr': 4198400}
        if section["name"] != ".text":
            continue

        textAddr = section["vaddr"]
        textOffset = section["paddr"]

    print(".text section: RVA: 0x{:x} FileOffset: 0x{:x}".format(textAddr, textOffset))
    print("")

    with open(filepath, "rb") as f:
        functionsStr = r2.cmd("aflj")
        functions = json.loads(functionsStr)

        methods = []
        for function in functions:
            if function["type"] != "fcn":
                continue

            offset = function["offset"] - textAddr + textOffset

            # disassembly for UI
            # has a lot of information (virtaddr, bytes), arrows etc.
            disasStr = r2.cmd("pD {} @{}".format(
                function["size"],
                function["offset"]
            ))


            # disassembly for fuzzy hash
            # just the plain opcodes as readable text
            if True:
                r2.cmd("e scr.color=0")
                r2.cmd("e asm.syntax=att")
                asmStr = r2.cmd("pDj {} @{}".format(
                    function["size"],
                    function["offset"]
                ))
                asm = json.loads(asmStr)
                print("Disassembly FuzzyHash as AT&T:")
                disasForHash = ""
                for ins in asm:
                    disasForHash += ins["opcode"] + "\n"

            # file content
            f.seek(offset)
            data = f.read(function["size"])

            # LLVM IL (bitcode)
            bitcode = ""
            if True:
                hexbytes = data.hex()
                cmd = "docker run --rm -it remill --arch amd64 --ir_out /dev/stdout --bytes {}".format(
                    hexbytes
                )
                output_stream = os.popen(cmd)
                bitcode = output_stream.read()
        
            method = Method()
            method.offset = offset
            method.rva = function["offset"]
            method.name = function["name"]
            method.disasmUi = disasStr
            method.disasmRaw = disasForHash
            method.data = data
            method.llvmBitcode = bitcode

            methods.append(method)
    
    return methods
