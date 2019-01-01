# vim: set fileencoding=utf-8 :

# «Annotate Yara Matches» for Hopper 4
# Copyright (c) 2018, Daniel Roethlisberger <daniel@roe.ch>
# https://github.com/droe/hopper-scripts
#
# Annotate all occurences of strings in one or multiple matching yara rules.
# Adds a summary at the beginning of the executable and for each string
# occurence.
#
# Uses yara via command line in order to avoid python module installation
# hassles; at least on macOS, Hopper uses system python2, not Brew or MacPorts.


import api
import os
import re
import subprocess
import tempfile


def parse_yara_meta(s):
    meta = {}
    while len(s) > 0:
        m = re.match('^([a-zA-Z0-9_]+)="', s)
        if not m:
            raise ValueError("yara meta syntax error: %s" % s[:10])
        k = m.group(1)
        v = None
        for i in range(len(k) + 2, len(s)):
            if s[i:i+1] == '"' and s[i-1:i] != '\\':
                v = s[len(k)+2:i].replace('\\"', '"')
                s = s[i+2:]
                break
        if v == None:
            raise ValueError("yara meta syntax error: %s" % s[:10])
        meta[k] = v
    return meta


def parse_yara_out(s):
    matches = []
    for line in s.splitlines():
        m = re.match('^([^ ]+) \\[(.*)\\] [^ ]+$', line)
        if m:
            rule = m.group(1)
            meta = m.group(2)
            meta = parse_yara_meta(meta)
            matches.append((rule, meta, []))
            continue
        m = re.match('^(0x[0-9a-fA-F]+):(\\$[^ ]+):.*$', line)
        if m:
            offset = int(m.group(1), 16)
            string = m.group(2)
            matches[-1][2].append((offset, string))
            continue
        raise ValueError("Syntax error in yara output: %s" % line)
    return matches


def yara(rulefile, data):
    tmpdir = tempfile.mkdtemp()
    with open(tmpdir + '/executable', 'w') as f:
        f.write(data)

    proc = subprocess.Popen(["@@yara@@", "-s", "-m", "-r", rulefile, tmpdir],
                            env={'LANG': 'en_US.UTF-8'},
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=False)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError("yara returned %i\n%s" % (proc.returncode, err))

    os.remove(tmpdir + '/executable')
    os.rmdir(tmpdir)
    return parse_yara_out(out)


def main():
    rulefile = api.ask_file("Yara rule", None, False)
    if not rulefile:
        return
    info = ["Matching yara rules from %s:" % rulefile]
    for rule, meta, strings in yara(rulefile, api.executable.bytes()):
        info.append("  rule %s" % rule)
        for k, v in meta.iteritems():
            info.append("    %s: %s" % (k, v))
        for fileoffset, name in strings:
            addr = api.otoa(fileoffset)
            info.append("    0x%x %x: %s" % (fileoffset, addr, name))
            comment = "yara: %s:%s" % (rule, name)
            api.add_comment(addr, comment)
    if len(info) == 1:
        info.append('  None')
    info = '\n'.join(info)
    api.add_comment(api.otoa(0), info)
    print(info)


if __name__ == '__main__':
    api.run(main)

