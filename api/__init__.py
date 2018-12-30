# vim: set fileencoding=utf-8 :

# Extended API for Hopper 4
# Copyright (c) 2018, Daniel Roethlisberger <daniel@roe.ch>
# https://github.com/droe/hopper-scripts
#
# Wraps the strictly procedural script API provided by Hopper 4 into an easier,
# more convenient, pythonic, expressive and object-oriented script API,
# resulting in less verbose and more readable scripts.


import traceback


class Document:
    def __init__(self, hdoc):
        self._hdoc = hdoc

    @property
    def raw(self):
        return self._hdoc


class Selection:
    def __init__(self, hdoc):
        self._sel = hdoc.getSelectionAddressRange()

    @property
    def start(self):
        return self._sel[0]

    @property
    def end(self):
        return self._sel[0]

    def __len__(self):
        return self.end - self.start


class Executable:
    def __init__(self, hdoc):
        self._hdoc = hdoc

    def bytes(self):
        return self._hdoc.produceNewExecutable()

    @property
    def path(self):
        return self._hdoc.getExecutableFilePath()


class Segment:
    def __init__(self, hseg):
        self._hseg = hseg

    @property
    def raw(self):
        return self._hseg

    def __contains__(self, x):
        if isinstance(x, (int, long)):
            return x >= self._hseg.getStartingAddress() and \
                   x < self._hseg.getStartingAddress() + self._hseg.getLength()
        raise NotImplementedError("__contains__ not implemented for: %r" % x)

    def bytes(self):
        return self._hseg.readBytes(self._hseg.getStartingAddress(),
                                    self._hseg.getLength())


class Segments:
    def __init__(self, hdoc):
        self._hdoc = hdoc

    def __iter__(self):
        segments = []
        for i in range(self._hdoc.getSegmentCount()):
            segments.append(Segment(self._hdoc.getSegment(i)))
        return iter(segments)


def ask_file(*args, **kwargs):
    return document.raw.askFile(*args, **kwargs)


def otoa(offset):
    return document.raw.getAddressFromFileOffset(offset)


def atoo(addr):
    return document.raw.getFileOffsetFromAddress(addr)


def get_comment(addr):
    for seg in segments:
        if not addr in seg:
            continue
        return seg.raw.getCommentAtAddress(addr)
    raise ValueError("Address %08x not in any segment" % addr)


def set_comment(addr, comment):
    for seg in segments:
        if not addr in seg:
            continue
        return seg.raw.setCommentAtAddress(addr, comment)
    raise ValueError("Address %08x not in any segment" % addr)


def add_comment(addr, comment):
    have = get_comment(addr)
    if have != None and have != '':
        comment = "%s\n%s" % (have, comment)
    set_comment(addr, comment)


def get_icomment(addr):
    for seg in segments:
        if not addr in seg:
            continue
        return seg.raw.getInlineCommentAtAddress(addr)
    raise ValueError("Address %08x not in any segment" % addr)


def set_icomment(addr, comment):
    for seg in segments:
        if not addr in seg:
            continue
        return seg.raw.setInlineCommentAtAddress(addr, comment)
    raise ValueError("Address %08x not in any segment" % addr)


def add_icomment(addr, comment):
    have = get_icomment(addr)
    if have != None and have != '':
        comment = "%s; %s" % (have, comment)
    set_icomment(addr, comment)


def run(script_main, script_globals_dict):
    hdoc = script_globals_dict['Document'].getCurrentDocument()

    global document
    document = Document(hdoc)

    global selection
    selection = Selection(hdoc)

    global executable
    executable = Executable(hdoc)

    global segments
    segments = Segments(hdoc)

    try:
        script_main()
    except Exception as e:
        hdoc.message(str(e), ['Ok'])
        traceback.print_exc()

