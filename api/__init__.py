# vim: set fileencoding=utf-8 :

# Extended API for Hopper 4
# Copyright (c) 2018, Daniel Roethlisberger <daniel@roe.ch>
# https://github.com/droe/hopper-scripts
#
# Wraps the strictly procedural script API provided by Hopper 4 into an easier,
# more convenient, pythonic, expressive and object-oriented script API,
# resulting in less verbose and more readable scripts.


import os
import subprocess
import sys
import traceback
import __main__ as main


class APIClipboard:
    CMDMAP = {
        'Darwin': ('pbcopy', 'pbpaste'),
        'Linux':  ('xsel -b -i', 'xsel -b -o'),
    }
    def __init__(self):
        uname = os.uname()[0]
        if uname in self.CMDMAP:
            self._cmd_copy, self._cmd_paste = self.CMDMAP[uname]
        else:
            raise NotImplementedError("%s not supported" % uname)

    def copy(self, s):
        proc = subprocess.Popen(self._cmd_copy,
                                env={'LANG': 'en_US.UTF-8'},
                                stdin=subprocess.PIPE,
                                shell=True)
        proc.communicate(s.encode('utf-8'))
        if proc.returncode != 0:
            msg = "%s failed with exit status %i" % (self._cmd_copy,
                                                     proc.returncode)
            raise RuntimeError(msg)

    def paste(self):
        proc = subprocess.Popen(self._cmd_paste,
                                env={'LANG': 'en_US.UTF-8'},
                                stdout=subprocess.PIPE,
                                shell=True)
        out, err = proc.communicate()
        if proc.returncode != 0:
            msg = "%s failed with exit status %i" % (self._cmd_paste,
                                                     proc.returncode)
            raise RuntimeError(msg)
        return out.decode('utf-8', errors='ignore')


class APIInstruction:
    def __init__(self, hseg, addr):
        self._hseg = hseg
        self.addr = addr
        if hseg.getTypeAtAddress(addr) in (main.Segment.TYPE_CODE,
                                           main.Segment.TYPE_PROCEDURE):
            self._hins = hseg.getInstructionAtAddress(addr)
            self._bytes = hseg.readBytes(addr,
                                         self._hins.getInstructionLength())
        else:
            self._hins = None
            self._bytes = hseg.readBytes(addr, 1)
            self._op = 'db'
            self._args = "0x%s" % hex(self)

    @property
    def raw(self):
        return self._hins

    def __len__(self):
        return len(self._bytes)

    def __hex__(self):
        return ''.join(x.encode('hex') for x in self._bytes)

    def __str__(self):
        return "%-8s %s" % (self.op, self.args)

    @property
    def op(self):
        if self._hins != None:
            return self._hins.getInstructionString()
        else:
            return self._op

    @property
    def args(self):
        if self._hins != None:
            insargs = []
            for i in range(self._hins.getArgumentCount()):
                insargs.append(self._hins.getRawArgument(i))
            return ', '.join(insargs)
        else:
            return self._args

    def arg(self, i):
        if self._hins != None:
            if i < 0 or i >= self._hins.getArgumentCount():
                raise IndexError("arg index out of range")
            return self._hins.getRawArgument(i)
        else:
            return None


class APIDocument:
    def __init__(self, hdoc):
        self._hdoc = hdoc

    @property
    def raw(self):
        return self._hdoc


class APISelection:
    def __init__(self, hdoc):
        self._hsel = hdoc.getSelectionAddressRange()
        self._raw_lines = hdoc.getRawSelectedLines()
        self._segments = segments.in_range(self.start, self.end)

    @property
    def start(self):
        return self._hsel[0]

    @property
    def end(self):
        return self._hsel[1]

    def __len__(self):
        return self.end - self.start

    def is_range(self):
        # Note: Raw lines contains the whole line if there was no selection,
        # so we cannot differentiate a one-line selection from no selection.
        return len(self._raw_lines) > 1

    def instructions(self):
        for seg in self._segments:
            start = max(seg.start, self.start)
            end = min(seg.end, self.end)
            for ins in seg.instructions(start, end):
                yield ins


class APIExecutable:
    def __init__(self, hdoc):
        self._hdoc = hdoc

    def bytes(self):
        return self._hdoc.produceNewExecutable()

    @property
    def path(self):
        return self._hdoc.getExecutableFilePath()

    @property
    def arch_bits(self):
        # FIXME Hopper API limitation; no access to actual bits
        if self._hdoc.is64Bits():
            return 64
        else:
            return 32

    @property
    def arch(self):
        # FIXME Hopper API limitation; no access to actual arch
        if self._hdoc.is64Bits():
            return 'x64'
        else:
            return 'x86'


class APISegment:
    def __init__(self, hseg):
        self._hseg = hseg

    @property
    def raw(self):
        return self._hseg

    @property
    def start(self):
        return self._hseg.getStartingAddress()

    @property
    def end(self):
        return self._hseg.getStartingAddress() + self._hseg.getLength()

    def __len__(self):
        length = self._hseg.getLength()
        if length > sys.maxint:
            raise ValueError("segment length > sys.maxint")
        return int(length)

    def __contains__(self, x):
        if isinstance(x, (int, long)):
            return x >= self.start and x < self.end
        raise NotImplementedError("__contains__ not implemented for: %r" % x)

    def bytes(self):
        return self._hseg.readBytes(self.start, len(self))

    def mark_as_undefined(self):
        self._hseg.markRangeAsUndefined(self.start, len(self))

    def disassemble(self):
        self._hseg.disassembleWholeSegment()

    def instructions(self, start=None, end=None):
        if start == None:
            start = self.start
        if end == None:
            end = self.end
        size = end - start
        buf = self._hseg.readBytes(start, size)
        pos = start
        while pos < end:
            ins = APIInstruction(self._hseg, pos)
            yield ins
            pos += len(ins)


class APISegments:
    def __init__(self, hdoc):
        self._hdoc = hdoc

    def __iter__(self):
        segs = []
        for i in range(self._hdoc.getSegmentCount()):
            segs.append(APISegment(self._hdoc.getSegment(i)))
        return iter(segs)

    def current(self):
        return self.by_addr(self._hdoc.getCurrentSegment().getStartingAddress())

    def by_addr(self, addr):
        for seg in self:
            if not addr in seg:
                continue
            return seg
        raise ValueError("Address %x not in any segment" % addr)

    def in_range(self, start, end):
        segs = []
        for seg in self:
            if start > seg.end or end < seg.start:
                continue
            segs.append(seg)
        return segs


def message(*args, **kwargs):
    return document.raw.message(*args, **kwargs)


def ask(*args, **kwargs):
    return document.raw.ask(*args, **kwargs)


def ask_file(*args, **kwargs):
    return document.raw.askFile(*args, **kwargs)


def ask_directory(*args, **kwargs):
    return document.raw.askDirectory(*args, **kwargs)


def otoa(offset):
    return document.raw.getAddressFromFileOffset(offset)


def atoo(addr):
    return document.raw.getFileOffsetFromAddress(addr)


def get_comment(addr):
    return segments.by_addr(addr).raw.getCommentAtAddress(addr)


def set_comment(addr, comment):
    return segments.by_addr(addr).raw.setCommentAtAddress(addr, comment)


def add_comment(addr, comment):
    have = get_comment(addr)
    if have != None and have != '':
        comment = "%s\n%s" % (have, comment)
    return set_comment(addr, comment)


def get_icomment(addr):
    return segments.by_addr(addr).raw.getInlineCommentAtAddress(addr)


def set_icomment(addr, comment):
    return segments.by_addr(addr).raw.setInlineCommentAtAddress(addr, comment)


def add_icomment(addr, comment):
    have = get_icomment(addr)
    if have != None and have != '':
        comment = "%s; %s" % (have, comment)
    return set_icomment(addr, comment)


def add_reference(addr, to_addr):
    segments.by_addr(addr).raw.addReference(addr, to_addr)


def get_label(addr):
    return document.raw.getNameAtAddress(addr)


def set_label(addr, label):
    return document.raw.setNameAtAddress(addr, label)


def mark_as_procedure(addr):
    return segments.by_addr(addr).raw.markAsProcedure(addr)


def selection():
    return APISelection(document.raw)


def run(script_main):
    script_name = os.path.basename(main.__file__)

    # assumption: current document does not change during script runtime
    hdoc = main.Document.getCurrentDocument()
    global document
    document = APIDocument(hdoc)
    global executable
    executable = APIExecutable(hdoc)
    global segments
    segments = APISegments(hdoc)
    global clipboard
    clipboard = APIClipboard()

    try:
        print("Executing %s" % script_name)
        script_main()
        print("Completed %s" % script_name)
    except Exception as e:
        hdoc.message(str(e), ['Ok'])
        traceback.print_exc()

