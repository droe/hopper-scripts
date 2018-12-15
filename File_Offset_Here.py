# vim: set fileencoding=utf-8 :

# «File Offset Here» for Hopper 4
# Copyright (c) 2018, Daniel Roethlisberger <daniel@roe.ch>
# https://github.com/droe/hopper-scripts
#
# Write the file offset at the cursor position into a prefix comment


import traceback


def main():
    doc = Document.getCurrentDocument()
    seg = doc.getCurrentSegment()
    sel = doc.getSelectionAddressRange()

    offset = seg.getFileOffsetForAddress(sel[0])
    comment = seg.getCommentAtAddress(sel[0])
    info = "File offset here: %x (%i)" % (offset, offset)
    if comment:
        comment = comment + "\n" + info
    else:
        comment = info
    seg.setCommentAtAddress(sel[0], comment)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        Document.getCurrentDocument().message(str(e), ['Ok'])
        traceback.print_exc()

