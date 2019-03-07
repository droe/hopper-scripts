# vim: set fileencoding=utf-8 :

# «Analyze Shellcode» for Hopper 4
# Copyright (c) 2018, Daniel Roethlisberger <daniel@roe.ch>
# https://github.com/droe/hopper-scripts
#
# This aims at detecting and annotating typical shellcode patterns in Hopper:
# - Known code blocks
# - Popping the return address from the stack as a way to reference data
# - Calling well-known imports by their name hash
# It is not very useful with fully handcrafted shellcode, unless one or more of
# these techniques was used.
#
# For best results:
# 1) Load shellcode at any base address, disabling automatic analysis
# 2) Modify -> Disassemble whole segment
# 3) Run this script
#
# The script asks if it should mark everything unknown and disassemble before
# walking all the disassembled instructions, looking for the above patterns.
# Except for this optional initial disassembling pass, the script does not
# attempt to change code to data and vice-versa.  For more tricky shellcode,
# typical workflow is to fix disassembly manually where needed and let the
# script run again to do the annotations.


import hopper_api as api


IMPORTS = (
    "kernel32.dll!LoadLibraryA",
    "kernel32.dll!GetVersion",
    "kernel32.dll!GetLastError",
    "kernel32.dll!SetUnhandledExceptionFilter",
    "kernel32.dll!CreateFileA",
    "kernel32.dll!DeleteFileA",
    "kernel32.dll!ReadFile",
    "kernel32.dll!ReadFileEx",
    "kernel32.dll!WriteFile",
    "kernel32.dll!WriteFileEx",
    "kernel32.dll!SetEvent",
    "kernel32.dll!GetTempPathA",
    "kernel32.dll!CloseHandle",
    "kernel32.dll!VirtualAlloc",
    "kernel32.dll!VirtualAllocEx",
    "kernel32.dll!VirtualFree",
    "kernel32.dll!CreateProcessA",
    "kernel32.dll!WriteProcessMemory",
    "kernel32.dll!CreateRemoteThread",
    "kernel32.dll!GetProcAddress",
    "kernel32.dll!WaitForSingleObject",
    "kernel32.dll!Sleep",
    "kernel32.dll!WinExec",
    "kernel32.dll!ExitProcess",
    "kernel32.dll!CreateThread",
    "kernel32.dll!ExitThread",
    "kernel32.dll!CreateNamedPipeA",
    "kernel32.dll!CreateNamedPipeW",
    "kernel32.dll!ConnectNamedPipe",
    "kernel32.dll!DisconnectNamedPipe",
    "kernel32.dll!lstrlenA",
    "ntdll.dll!RtlCreateUserThread",
    "ntdll.dll!RtlExitUserThread",
    "advapi32.dll!RevertToSelf",
    "advapi32.dll!StartServiceCtrlDispatcherA",
    "advapi32.dll!RegisterServiceCtrlHandlerExA",
    "advapi32.dll!SetServiceStatus",
    "advapi32.dll!OpenSCManagerA",
    "advapi32.dll!OpenServiceA",
    "advapi32.dll!ChangeServiceConfig2A",
    "advapi32.dll!CloseServiceHandle",
    "user32.dll!GetDesktopWindow",
    "ws2_32.dll!WSAStartup",
    "ws2_32.dll!WSASocketA",
    "ws2_32.dll!WSAAccept",
    "ws2_32.dll!bind",
    "ws2_32.dll!listen",
    "ws2_32.dll!accept",
    "ws2_32.dll!closesocket",
    "ws2_32.dll!connect",
    "ws2_32.dll!recv",
    "ws2_32.dll!send",
    "ws2_32.dll!setsockopt",
    "ws2_32.dll!gethostbyname",
    "wininet.dll!InternetOpenA",
    "wininet.dll!InternetConnectA",
    "wininet.dll!HttpOpenRequestA",
    "wininet.dll!HttpSendRequestA",
    "wininet.dll!InternetErrorDlg",
    "wininet.dll!InternetReadFile",
    "wininet.dll!InternetSetOptionA",
    "winhttp.dll!WinHttpOpen",
    "winhttp.dll!WinHttpConnect",
    "winhttp.dll!WinHttpOpenRequest",
    "winhttp.dll!WinHttpSendRequest",
    "winhttp.dll!WinHttpReceiveResponse",
    "winhttp.dll!WinHttpReadData",
    "dnsapi.dll!DnsQuery_A",
    "pstorec.dll!PStoreCreateInstance",
)


# First match per start address wins.
KNOWN_BLOCKS = (
{
    'name': 'dll_call_by_hash',
    'proc': True,
    'comment': """
Metasploit x86 call-by-hash by Stephen Fewer
https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_api.asm
""",
    'start': (
        0x60,                           # pushal
        0x89, 0xE5,                     # mov       ebp, esp
        0x31, 0xD2,                     # xor       edx, edx
        0x64, 0x8B, 0x52, 0x30,         # mov       edx, dword [fs:edx+0x30]
        0x8B, 0x52, 0x0C,               # mov       edx, dword [edx+0xc]
        0x8B, 0x52, 0x14,               # mov       edx, dword [edx+0x14]
    ),
    'end': (
        0x61,                           # popal
        0x59,                           # pop       ecx
        0x5A,                           # pop       edx
        0x51,                           # push      ecx
        0xFF, 0xE0,                     # jmp       eax
        0x58,                           # pop       eax
        0x5F,                           # pop       edi
        0x5A,                           # pop       edx
        0x8B, 0x12,                     # mov       edx, dword [edx]
        0xEB, 0x86,                     # jmp       <offset>
    ),
}, {
    'name': 'dll_call_by_hash',
    'proc': True,
    'comment': """
Metasploit x64 call-by-hash by Stephen Fewer
https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/block/block_api.asm
""",
    'start': (
        0x41, 0x51,                     # push      r9
        0x41, 0x50,                     # push      r8
        0x52,                           # push      rdx
        0x51,                           # push      rcx
        0x56,                           # push      rsi
        0x48, 0x31, 0xD2,               # xor       rdx, rdx
        0x65, 0x48, 0x8B, 0x52, 0x60,   # mov       rdx, qword [gs:rdx+0x60]
        0x48, 0x8B, 0x52, 0x18,         # mov       rdx, qword [rdx+0x18]
        0x48, 0x8B, 0x52, 0x20,         # mov       rdx, qword [rdx+0x20]
    ),
    'end': (
        0x5E,                           # pop       rsi
        0x59,                           # pop       rcx
        0x5A,                           # pop       rdx
        0x41, 0x58,                     # pop       r8
        0x41, 0x59,                     # pop       r9
        0x41, 0x5A,                     # pop       r10
        0x48, 0x83, 0xEC, 0x20,         # sub       rsp, 0x20
        0x41, 0x52,                     # push      r10
        0xFF, 0xE0,                     # jmp       rax
        0x58,                           # pop       rax
        0x41, 0x59,                     # pop       r9
        0x5A,                           # pop       rdx
        0x48, 0x8B, 0x12,               # mov       rdx, qword [rdx]
        0xE9, 0x4F, 0xFF, 0xFF, 0xFF,   # jmp       <offset>
    ),
},
)


class ImportHashes:
    CHECK = 'kernel32.dll!LoadLibraryA'
    METHODS = ('msf', )
    CHECKSUMS = {
        'msf': 0x0726774C,
    }

    def __init__(self):
        self._hashmaps = {}
        for which in self.METHODS:
            #print('Method %s' % which)
            self._hashmaps[which] = {}
            for spec in IMPORTS:
                m, f = spec.split('!')
                h = self._hash(which, m, f)
                if not h in self._hashmaps[which]:
                    #print('Adding 0x%08x %s' % (h, spec))
                    self._hashmaps[which][h] = spec
            assert(self.CHECKSUMS[which] in self._hashmaps[which])
            assert(self._hashmaps[which][self.CHECKSUMS[which]] == self.CHECK)

    def __contains__(self, x):
        return any([x in self._hashmaps[t] for t in self._hashmaps])

    def __getitem__(self, k):
        # Currently returns the first match; should improve this to handle
        # collisions between different hashing methods in a more useful way
        for t in self._hashmaps:
            if k in self._hashmaps[t]:
                return self._hashmaps[t][k]
        raise KeyError(k)

    def _ror32(self, x, bits):
        return (x >> bits | x << (32 - bits)) & 0xFFFFFFFF

    def _wide(self, s):
        out = []
        for c in s:
            out.append(c)
            out.append("\x00")
        return ''.join(out)

    def _hash_ror(self, module, function, bits):
        mhash = 0
        fhash = 0
        for c in self._wide(module + "\x00"):
            mhash = self._ror32(mhash, bits) + ord(c)
        for c in function + "\x00":
            fhash = self._ror32(fhash, bits) + ord(c)
        return (mhash + fhash) & 0xFFFFFFFF

    def _hash(self, which, module, function):
        if which == 'msf':
            return self._hash_ror(module.upper(), function, 13)
        raise NotImplementedError(which)


class KnownBlocksHelper:
    # XXX this works, but badly needs a rewrite

    def __init__(self, seg, addr, size):
        self._seg = seg
        self._addr = addr
        self._size = size
        self._buf = seg.readBytes(addr, size)

    def compare_bytes(self, pos, literals):
        if pos < self._addr or pos >= self._addr + self._size:
            raise ValueError("pos out of bounds")
        if pos + len(literals) > self._addr + self._size:
            return False
        for i in range(len(literals)):
            if self._buf[pos + i - self._addr] != chr(literals[i]):
                return False
        return True

    def find_bytes(self, pos, literals):
        if pos < self._addr or pos >= self._addr + self._size:
            raise ValueError("pos out of bounds")
        if pos + len(literals) > self._addr + self._size:
            return -1
        remaining_size = self._size - (pos - self._addr)
        for i in range(remaining_size - len(literals)):
            if self.compare_bytes(pos + i, literals):
                return pos + i
        return -1

    def yield_matches(self, literals):
        match_addr = self.find_bytes(self._addr, literals)
        while match_addr != -1:
            yield match_addr
            match_addr = self.find_bytes(match_addr + 1, literals)

    def yield_known_blocks(self):
        matched_addrs = set()
        for block in KNOWN_BLOCKS:
            for start_addr in self.yield_matches(block['start']):
                if start_addr in matched_addrs:
                    continue
                if 'end' in block:
                    end_addr = self.find_bytes(start_addr + 1, block['end'])
                    if not end_addr > start_addr:
                        # if end cannot be found here, it will never be found
                        break
                    end_addr += len(block['end'])
                else: # block['size']?
                    end_addr = start_addr + len(block['start'])
                yield block, start_addr, end_addr
                matched_addrs.add(start_addr)


def first_stack_instruction(where, pos, n=16):
    for ins in where.instructions(pos):
        op = ins.op
        if ins.raw.isAConditionalJump() or ins.raw.isAnInconditionalJump():
            break
        if op in ('hlt', 'int', 'enter', 'leave'):
            break
        if op.startswith('ret') or op.startswith('iret') or \
           op.startswith('sys'):
            break
        if op.startswith('push') or op.startswith('pop'):
            return ins
        if ins.addr > pos + n:
            break
    return None


def main():
    print("Arch: %s" % api.executable.arch)

    seg = api.segments.current()
    sel = api.selection()

    if sel.is_range():
        print("operating on current selection")
        shellcode = sel
    else:
        ans = api.message("Mark segment as undefined and disassemble?",
                          ['Cancel', 'No', 'Yes'])
        if ans == 0:
            return
        elif ans == 2:
            seg.mark_as_undefined()
            seg.disassemble()

        print("operating on current segment")
        shellcode = seg

    print("analyzing range %x:%x" % (shellcode.start, shellcode.end))

    # identify and mark known blocks
    kbhelper = KnownBlocksHelper(seg.raw,
                                 shellcode.start, len(shellcode))
    for block, start_addr, end_addr in kbhelper.yield_known_blocks():
        print("---> found known block '%s' at %x" % (block['name'],
                                                     start_addr))
        name = "%s_%x" % (block['name'], start_addr)
        api.set_label(start_addr, name)
        if 'proc' in block and block['proc']:
            api.mark_as_procedure(start_addr)
        if 'comment' in block and block['comment']:
            api.set_comment(start_addr, block['comment'])
        if 'inline_comment' in block and block['inline_comment']:
            api.set_icomment(start_addr, block['inline_comment'])
        if 'offsets' in block:
            for offset, offset_name in block['offsets']:
                offset_addr = start_addr + offset
                offset_name = "%s_%x" % (offset_name, offset_addr)
                api.set_label(offset_addr, offset_name)

    # xref or annotate call, pop reg combo
    for ins in shellcode.instructions():
        if ins.op != 'call':
            continue
        arg = ins.arg(0)
        if not arg.startswith('0x'):
            continue
        target_addr = int(arg, 16)
        stack_ins = first_stack_instruction(shellcode, target_addr)
        if stack_ins == None or stack_ins.op != 'pop':
            continue

        if api.get_label(target_addr) == None:
            api.set_label(target_addr, "pop_retaddr_%x" % target_addr)

        #reg = stack_ins.arg(0)
        print("---> found call + pop retaddr combo at %x -> %x" % (
            ins.addr, target_addr))

        loaded_addr = ins.addr + len(ins)
        if loaded_addr == shellcode.end:
            # Hopper silently ignores xrefs to EOF
            api.set_icomment(stack_ins.addr, "end of shellcode")
        else:
            api.add_reference(stack_ins.addr, loaded_addr)
            if api.get_label(loaded_addr) == None:
                api.set_label(loaded_addr, "retaddr_%x" % loaded_addr)


    # annotate known import hashes
    hashes = ImportHashes()
    hash_ops = {
        # op, arg index
        'push':     0,
        'mov':      1,
        'movabs':   1,
    }
    for ins in shellcode.instructions():
        op = ins.op
        if not op in hash_ops:
            continue
        arg = ins.arg(hash_ops[op])
        if not arg.startswith('0x'):
            continue
        cand_hash = int(arg, 16)
        if cand_hash in hashes:
            name = hashes[cand_hash]
            api.set_icomment(ins.addr, name)


if __name__ == '__main__':
    api.run(main)

