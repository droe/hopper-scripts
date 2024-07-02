# vim: set fileencoding=utf-8 :

# «Save Selection As Bytes» for Hopper 5
# Copyright (c) 2018, 2023-2024, Daniel Roethlisberger <daniel@roe.ch>
# https://github.com/droe/hopper-scripts
#
# Save selection to a file, optionally XOR decoded.


import hopper_api as api
import binascii
from itertools import cycle


def unhexlify(s):
    if len(s) % 2 != 0:
        s = '0' + s
    return binascii.unhexlify(s)


def xorcrypt(buf, key):
    if len(key) == 0:
        return buf
    k = cycle(key)
    return bytes(b ^ next(k) for b in buf)


def main():
    addr = api.selection().start
    size = api.selection().end - addr
    if size == None:
        return
    blob = api.document.read(addr, size)

    ans = api.ask_hex("XOR key in hex (optional)")
    if ans == None:
        return
    if len(ans) == 0:
        key = b'\x00'
    else:
        key = unhexlify(ans)
    blob = xorcrypt(blob, key)

    filename = api.ask_file("Save bytes to", None, True)
    if filename == None:
        return

    with open(filename, 'wb') as f:
        f.write(blob)


if __name__ == '__main__':
    api.run(main)
