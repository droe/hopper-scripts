# vim: set fileencoding=utf-8 :

# Extended API for Hopper 4
# Copyright (c) 2018, Daniel Roethlisberger <daniel@roe.ch>
# https://github.com/droe/hopper-scripts
#
# Wraps the strictly procedural script API provided by Hopper 4 into an easier,
# more convenient, pythonic, expressive and object-oriented script API,
# resulting in less verbose and more readable scripts.


import sys
import traceback


class APIDocument:
    def __init__(self, hdoc):
        self._hdoc = hdoc

    @property
    def raw(self):
        return self._hdoc


class APISelection:
    def __init__(self, hdoc):
        self._hsel = hdoc.getSelectionAddressRange()
        self._hseg = hdoc.getCurrentSegment()

    @property
    def start(self):
        return self._hsel[0]

    @property
    def end(self):
        return self._hsel[0]

    def __len__(self):
        return self.end - self.start

    def is_single_instruction(self):
        typ = self._hseg.getTypeAtAddress(self._hsel[0])
        #if typ in (Segment.TYPE_EXTERN,):
        if typ in (61,):
            return self._hsel[1] == self._hsel[0] + (executable.arch_bits / 8)
        if typ in (Segment.TYPE_CODE, Segment.TYPE_PROCEDURE):
            hins = self._hseg.getInstructionAtAddress(self._hsel[0])
            return self._hsel[1] == self._hsel[0] + hins.getInstructionLength()
        # TODO handle other types
        raise RuntimeError("Selection starts with unhandled type %s (%i)" % ( \
                           self._hseg.stringForType(typ), typ))


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


def run(script_main, script_globals_dict):
    global Document
    Document = script_globals_dict['Document']
    global Segment
    Segment = script_globals_dict['Segment']

    # assumption: current document does not change during script runtime

    hdoc = Document.getCurrentDocument()
    global document
    document = APIDocument(hdoc)
    global executable
    executable = APIExecutable(hdoc)
    global segments
    segments = APISegments(hdoc)

    try:
        script_main()
    except Exception as e:
        hdoc.message(str(e), ['Ok'])
        traceback.print_exc()

