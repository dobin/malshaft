import r2pipe
import json
import hexdump
import os
import sys

from typing import List
from pyvex.stmt import IRStmt

from pyvexsupport import pyvexAnalyze, BasicBlock, resolveMethodBbNext
from remillsupport import remillToLlvm

from model import * 


def analyzer(filepath) -> PeFile:
    r2 = r2pipe.open(filepath)
    r2.cmd("aaa")  # analyze

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

    symbols = []
    with open(filepath, "rb") as f:
        # list all functions
        # see doc/r2-aflj.json for example json entry
        functionsStr = r2.cmd("afllj")
        functions = json.loads(functionsStr)

        methods: List[Method] = []
        for function in functions:
            # save it as a symbol to reference later (resolver)
            if function["type"] != "fcn":
                symbols.append(Symbol(function["offset"], function["name"]))
                continue
            offset = function["offset"] - textAddr + textOffset

            # disassembly (for UI)
            # has a lot of information (virtaddr, bytes), arrows etc.
            # see doc/r2-pD.txt
            disasStr = r2.cmd("pD {} @{}".format(
                function["size"],
                function["offset"]
            ))

            # disassembly for fuzzy hash
            # just the plain opcodes as readable text
            # see doc/r2-pDj.json
            if True:
                r2.cmd("e scr.color=0")
                r2.cmd("e asm.syntax=att")
                asmStr = r2.cmd("pDj {} @{}".format(
                    function["size"],
                    function["offset"]
                ))
                asm = json.loads(asmStr)
                disasForHash = ""
                for ins in asm:
                    disasForHash += ins["opcode"] + "\n"

            # file content
            f.seek(offset)
            data = f.read(function["size"])

            # LLVM IL (bitcode)
            # see doc/llvm.txt for an example
            # No need anymore
            bitcode = ""
            if False:
                bitcode = remillToLlvm(data)

            # method call refs
            callrefs = []
            if 'callrefs' in function:
                for ref in function["callrefs"]:
                    if ref["type"] != "CALL":
                        continue
                    destName = ''
                    for fu in functions:
                        if fu["offset"] == ref["addr"]:
                            destName = fu["name"]
                            break

                    callrefs.append({
                        "addr": ref["addr"],
                        "name": destName
                    })

            # PyVEX Stuff
            vexBB: List[BasicBlock] = pyvexAnalyze(data, function["offset"])

            method = Method()
            method.offset = offset
            method.rva = function["offset"]
            method.name = function["name"]
            method.disasmUi = disasStr
            method.disasmRaw = disasForHash
            method.data = data
            method.llvmBitcode = bitcode
            method.callrefs = callrefs
            method.vexBB = vexBB
            method.vexStr = ""

            methods.append(method)
    
    peFile = PeFile(
        methods,
        symbols,
        sections
    )
    return peFile
