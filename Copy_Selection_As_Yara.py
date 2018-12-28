# vim: set fileencoding=utf-8 :

# «Copy Selection As Yara» for Hopper 4
# Copyright (c) 2018, Daniel Roethlisberger <daniel@roe.ch>
# https://github.com/droe/hopper-scripts
#
# Copy the current selection to clipboard in yara syntax


import os
import traceback
import subprocess
import re


if os.uname()[0] == 'Darwin':
    CMD = 'pbcopy'
elif os.uname()[0] == 'Linux':
    CMD = 'xsel -b'
else:
    raise NotImplementedError("%s not supported" % os.uname()[0])


def pbcopy(s):
    proc = subprocess.Popen(CMD,
                            env={'LANG': 'en_US.UTF-8'},
                            stdin=subprocess.PIPE,
                            shell=True)
    proc.communicate(s.encode('utf-8'))


def render(binary, assembly):
    pattern = " ".join(binary[i:i+2] for i in range(0, len(binary), 2))
    return "      %-34s// %s" % (pattern, assembly)


def bytes2hex(b):
    return ''.join(x.encode('hex') for x in b)


class InstructionReader(object):
    def __init__(self, seg, addr, size):
        self._seg = seg
        self._addr = addr
        self._size = size
        self._buf = seg.readBytes(addr, size)

    def yield_instructions(self, pos):
        while pos < self._addr + self._size:
            if self._seg.getTypeAtAddress(pos) in (Segment.TYPE_CODE,
                                                   Segment.TYPE_PROCEDURE):
                ins = self._seg.getInstructionAtAddress(pos)
                inslen = ins.getInstructionLength()
                inshex = bytes2hex(self._seg.readBytes(pos, inslen))
                insop = ins.getInstructionString()
                insargs = []
                for i in range(ins.getArgumentCount()):
                    insargs.append(ins.getRawArgument(i))
                insargs = ', '.join(insargs)
            else:
                inslen = 1
                inshex = bytes2hex(self._seg.readBytes(pos, inslen))
                insop = 'db'
                insargs = "0x%s" % inshex
            insasm = "%-8s %s" % (insop, insargs)
            yield pos, inslen, inshex, insasm
            pos += inslen


def main():
    doc = Document.getCurrentDocument()
    seg = doc.getCurrentSegment()
    sel = doc.getSelectionAddressRange()

    out = []
    ir = InstructionReader(seg, sel[0], sel[1] - sel[0])
    for pos, inslen, inshex, insasm in ir.yield_instructions(sel[0]):
        out.append(render(inshex, insasm))
    pbcopy('\n'.join(out + ['']))


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        Document.getCurrentDocument().message(str(e), ['Ok'])
        traceback.print_exc()

