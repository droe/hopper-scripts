# vim: set fileencoding=utf-8 :

# «Copy Selection As Yara» for Hopper 4
# Copyright (c) 2018, Daniel Roethlisberger <daniel@roe.ch>
#
# Copy the current selection to clipboard in yara syntax


import traceback
import subprocess
import re


def pbcopy(s):
    proc = subprocess.Popen('pbcopy',
                            env={'LANG': 'en_US.UTF-8'},
                            stdin=subprocess.PIPE)
    proc.communicate(s.encode('utf-8'))


def render(binary, assembly):
    pattern = " ".join(binary[i:i+2] for i in range(0, len(binary), 2))
    return "      %-34s// %s" % (pattern, assembly)


def main():
    doc = Document.getCurrentDocument()
    seg = doc.getCurrentSegment()
    sel = doc.getSelectionAddressRange()

    out = []
    pattern = re.compile('^\\S+\\s+(\\S+)\\s+(.*?)\\s*(?:;.*)?$')
    for line in doc.getRawSelectedLines():
        m = pattern.match(line)
        if not m:
            print(" *** skipping line: %s" % line)
            continue
        out.append(render(m.group(1), m.group(2)))
    pbcopy('\n'.join(out + ['']))


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        Document.getCurrentDocument().message(str(e), ['Ok'])
        traceback.print_exc()

