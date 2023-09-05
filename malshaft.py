#!/usr/bin/python3

import r2pipe
import json
import hexdump
import ssdeep
import os

filepath = "/home/dobin/repos/avred/tests/data/test.exe"

r2 = r2pipe.open(filepath)
r2.cmd("aaa")


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
    for function in functions:
        if function["type"] != "fcn":
            continue
        offset = function["offset"] - textAddr + textOffset
        print("Function: RVA: 0x{:x} FileOffset:{}: {} ({})".format(
            function["offset"],
            offset,
            function["name"],
            function["type"],
        ))
    print("")

    for function in functions:
        if function["type"] != "fcn":
            continue

        print("-----------------------------------------------------")
        print("")

        offset = function["offset"] - textAddr + textOffset
        print("Function: RVA: 0x{:x} FileOffset:{}: {} ({})".format(
            function["offset"],
            offset,
            function["name"],
            function["type"],
        ))
        print("")

        # disassembly for UI
        # has a lot of information (virtaddr, bytes), arrows etc.
        disasStr = r2.cmd("pD {} @{}".format(
            function["size"],
            function["offset"]
        ))
        print("Disassembly UI:")
        print(disasStr)

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
                print("  {}".format(ins["opcode"]))
            print("")

        # file content
        f.seek(offset)
        data = f.read(function["size"])
        print("Hexdump:")
        hexdump.hexdump(data)
        print("")

        # LLVM IL (bitcode)
        hexbytes = data.hex()
        cmd = "docker run --rm -it remill --arch amd64 --ir_out /dev/stdout --bytes {}".format(
            hexbytes
        )
        output_stream = os.popen(cmd)
        bitcode = output_stream.read()
        print("Bitcode:")
        #print(bitcode)
        convertRemill(bitcode)

        # fuzzy hash
        print("Fuzzy hash: {}".format(ssdeep.hash(data)))

        print("")
        break
