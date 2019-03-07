# vim: set fileencoding=utf-8 :

# «Save Bytes From Here» for Hopper 4
# Copyright (c) 2018, Daniel Roethlisberger <daniel@roe.ch>
# https://github.com/droe/hopper-scripts
#
# Save n bytes from current position to a file, optionally XOR decoded.


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
    addr = api.selection().start
    size = api.ask_int("Number of bytes")
    if size == None:
        return
    blob = api.document.read(addr, size)

    ans = api.ask_hex("XOR key in hex (optional)")
    if ans == None:
        return
    if len(ans) == 0:
        key = '\x00'
    else:
        key = unhexlify(ans)
    blob = xorcrypt(blob, key)

    filename = api.ask_file("Save bytes to", None, True)

    with open(filename, 'w') as f:
        f.write(blob)


if __name__ == '__main__':
    api.run(main)

