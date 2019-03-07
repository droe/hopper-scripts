# vim: set fileencoding=utf-8 :

# «Annotate Stack Strings In Selection» for Hopper 4
# Copyright (c) 2018, Daniel Roethlisberger <daniel@roe.ch>
# https://github.com/droe/hopper-scripts
#
# Annotate stack strings in the current selection with their decoded string
# form.  Supports XOR decryption using a single or multi-byte key and no
# feedback.


import hopper_api as api
import binascii
from itertools import cycle, izip


def unhexlify(s):
    if len(s) % 2 != 0:
        s = '0' + s
    return binascii.unhexlify(s)


def xorcrypt(s, key):
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in izip(s, cycle(key)))


def main():
    ans = api.ask_hex("XOR key in hex (optional)")
    if ans == None:
        return
    if len(ans) == 0:
        key = '\x00'
    else:
        key = unhexlify(ans)

    for ins in api.selection().instructions():
        if ins.op in ('mov', 'movabs'):
            data = ins.arg(1)
        else:
            continue
        if not data.startswith('0x'):
            continue
        data = unhexlify(data[2:])
        data = reversed(data)
        data = xorcrypt(data, key)
        api.set_icomment(ins.addr, repr(data))


if __name__ == '__main__':
    api.run(main)

