# vim: set fileencoding=utf-8 :

# «File Offset Here» for Hopper 4
# Copyright (c) 2018, Daniel Roethlisberger <daniel@roe.ch>
# https://github.com/droe/hopper-scripts
#
# Write the file offset at the cursor position into a prefix comment


import api


def main():
    addr = api.selection().start
    offset = api.atoo(addr)
    comment = "File offset here: %x (%i)" % (offset, offset)
    api.add_comment(addr, comment)


if __name__ == '__main__':
    api.run(main)

