import os


def remillToLlvm(data):
    hexbytes = data.hex()
    cmd = "docker run --rm -it remill --arch amd64 --ir_out /dev/stdout --bytes {}".format(
        hexbytes
    )
    output_stream = os.popen(cmd)
    bitcode = output_stream.read()
    return bitcode


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

