#!/usr/bin/python3

import argparse
from analyzer import *


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="File to scan")
    parser.add_argument("-c", "--csv", help="CSV output", default=False, action='store_true')
    args = parser.parse_args()

    if not args.file:
        print("Give file")
        exit(1)

    filepath = args.file
    methods = analyzer(filepath)

    if args.csv:
        printCsv(os.path.basename(args.file), methods)
    else:
        printDetails(methods)


def printCsv(filename, methods):
    for method in methods:
        print("{};{};{}".format(
            filename,
            method.name,
            method.fuzzyHash()
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

        # fuzzy hash
        print("Fuzzy hash: {}".format(method.fuzzyHash()))
        print("")

if __name__ == "__main__":
    main()
