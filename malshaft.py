#!/usr/bin/python3

import argparse
from analyzer import *

from remillsupport import convertRemill
from model import PeFile
from pyvexsupport import augmentVex


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="File to scan")
    parser.add_argument("-c", "--csv", help="CSV output", default=False, action='store_true')
    args = parser.parse_args()

    if not args.file:
        print("Give file")
        exit(1)

    filepath = args.file
    peFile: PeFile = analyzer(filepath)
    augmentVex(peFile)

    if args.csv:
        printCsv(os.path.basename(args.file), peFile.methods)
    else:
        printDetails(peFile.methods)


def printCsv(filename, methods):
    for method in methods:
        print("{};{};{};0x{:x}".format(
            filename,
            method.name,
            method.fuzzyHash(),
            method.rva,
        ))


def printDetails(methods):
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

        print("Callrefs:")
        for callref in method.callrefs:
            print("  {:x} {}".format(callref['addr'], callref['name']))
        print("")

        #print("VEX:")
        print("VEX Str:")
        print("{}".format(method.vexStr))

        # fuzzy hash
        print("Fuzzy hash: {}".format(method.fuzzyHash()))
        print("")

if __name__ == "__main__":
    main()
