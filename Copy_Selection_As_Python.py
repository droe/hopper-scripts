# vim: set fileencoding=utf-8 :

# «Copy Selection As Python» for Hopper 4
# Copyright (c) 2018, Daniel Roethlisberger <daniel@roe.ch>
# https://github.com/droe/hopper-scripts
#
# Copy the current selection to clipboard in python syntax


import api
import re


def render(binary, assembly):
    pattern = ", 0x".join(binary[i:i+2] for i in range(0, len(binary), 2))
    pattern = "0x%s," % pattern
    return "    %-36s# %s" % (pattern, assembly)


def main():
    out = []
    for ins in api.selection().instructions():
        out.append(render(hex(ins), str(ins)))
    api.clipboard.copy('\n'.join(out + ['']))


if __name__ == '__main__':
    api.run(main)

