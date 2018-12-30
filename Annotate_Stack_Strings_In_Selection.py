# vim: set fileencoding=utf-8 :

# «Annotate Stack Strings In Selection» for Hopper 4
# Copyright (c) 2018, Daniel Roethlisberger <daniel@roe.ch>
# https://github.com/droe/hopper-scripts
#
# Annotate stack strings in the current selection with their decoded string
# form.  Supports XOR decryption using a single or multi-byte key and no
# feedback.

# TODO convert to new API


import traceback
import binascii
from itertools import cycle, izip


def unhexlify(s):
    if len(s) % 2 != 0:
        s = '0' + s
    return binascii.unhexlify(s)


def xorcrypt(s, key):
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in izip(s, cycle(key)))


class InstructionReader:
    def __init__(self, seg, addr, size):
        self._seg = seg
        self._addr = addr
        self._size = size
        self._buf = seg.readBytes(addr, size)

    def yield_instructions(self, pos):
        while pos < self._addr + self._size:
            if self._seg.getTypeAtAddress(pos) not in (Segment.TYPE_CODE,
                                                       Segment.TYPE_PROCEDURE):
                pos += 1
                continue
            ins = self._seg.getInstructionAtAddress(pos)
            yield pos, ins
            pos += ins.getInstructionLength()


def main():
    doc = Document.getCurrentDocument()
    seg = doc.getCurrentSegment()
    sel = doc.getSelectionAddressRange()

    ans = doc.ask("XOR key in hex (optional)")
    if ans == None:
        return
    ans = ans.strip()
    if ans.startswith('0x'):
        ans = ans[2:]
    if ans.endswith('h'):
        ans = ans[:-1]
    if len(ans) == 0:
        key = '\x00'
    else:
        key = unhexlify(ans)

    range_addr = sel[0]
    range_size = sel[1] - sel[0]
    reader = InstructionReader(seg, range_addr, range_size)

    for addr, ins in reader.yield_instructions(range_addr):
        op = ins.getInstructionString()
        if op in ('mov', 'movabs'):
            data = ins.getRawArgument(1)
        else:
            continue
        if not data.startswith('0x'):
            continue
        data = unhexlify(data[2:])
        data = reversed(data)
        data = xorcrypt(data, key)
        seg.setInlineCommentAtAddress(addr, repr(data))


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        Document.getCurrentDocument().message(str(e), ['Ok'])
        traceback.print_exc()

