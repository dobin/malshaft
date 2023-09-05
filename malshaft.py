#!/usr/bin/python3

import argparse
from analyzer import *


parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="File to scan")
args = parser.parse_args()

if not args.file:
    print("Give file")
    exit(1)

filepath = args.file

methods = analyzer(filepath)

for method in methods: 
    print("-----------------------------------------------------")
    print("")

    print("Function: RVA: 0x{:x} FileOffset:{}: {} ({})".format(
        method.rva,
        method.offset,
        method.name,
        "",
    ))
    print("")

    print("Disassembly UI:")
    print(method.disasmUi)
    print("")

    print("Disassembly Raw:")
    print(method.disasmRaw)
    print("")
        
    print("Hexdump:")
    hexdump.hexdump(method.data)
    print("")

    print("Bitcode:")
    print(convertRemill(method.llvmBitcode))
    print("")

    # fuzzy hash
    print("Fuzzy hash: {}".format(ssdeep.hash(method.data)))
    print("")
