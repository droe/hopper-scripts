# vim: set fileencoding=utf-8 :

# «Copy Selection As Yara» for Hopper 4
# Copyright (c) 2018, Daniel Roethlisberger <daniel@roe.ch>
# https://github.com/droe/hopper-scripts
#
# Copy the current selection to clipboard in yara syntax


import api
import re


def render(binary, assembly):
    pattern = " ".join(binary[i:i+2] for i in range(0, len(binary), 2))
    return "      %-34s// %s" % (pattern, assembly)


def main():
    out = []
    for ins in api.selection().instructions():
        out.append(render(hex(ins), str(ins)))
    api.clipboard.copy('\n'.join(out + ['']))


if __name__ == '__main__':
    api.run(main)

