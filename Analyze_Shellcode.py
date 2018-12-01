# vim: set fileencoding=utf-8 :

# «Analyze Shellcode» for Hopper 4
# Copyright (c) 2018, Daniel Roethlisberger <daniel@roe.ch>
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
# The script asks if it should mark everything unknown and disassemble.
# Press cancel if you made manual adjustments that you want to keep.

# TODO - add more known code blocks
# TODO - add hashes for other hashing methods than Metasploit's
# TODO - improve performance using newer Hopper API functions


import traceback


# Hash constants will be annotated with an inline comment naming the DLL and
# imported function that is references.
DLL_FUNC_HASHES = {
    0x5BAE572D: "kernel32.dll!WriteFile",
    0x4FDAF6DA: "kernel32.dll!CreateFileA",
    0x13DD2ED7: "kernel32.dll!DeleteFileA",
    0xE449F330: "kernel32.dll!GetTempPathA",
    0x528796C6: "kernel32.dll!CloseHandle",
    0x863FCC79: "kernel32.dll!CreateProcessA",
    0xE553A458: "kernel32.dll!VirtualAlloc",
    0x300F2F0B: "kernel32.dll!VirtualFree",
    0x0726774C: "kernel32.dll!LoadLibraryA",
    0x7802F749: "kernel32.dll!GetProcAddress",
    0x601D8708: "kernel32.dll!WaitForSingleObject",
    0x876F8B31: "kernel32.dll!WinExec",
    0x9DBD95A6: "kernel32.dll!GetVersion",
    0xEA320EFE: "kernel32.dll!SetUnhandledExceptionFilter",
    0x56A2B5F0: "kernel32.dll!ExitProcess",
    0x0A2A1DE0: "kernel32.dll!ExitThread",
    0x5DE2C5AA: "kernel32.dll!GetLastError",
    0x6F721347: "ntdll.dll!RtlExitUserThread",
    0x23E38427: "advapi32.dll!RevertToSelf",
    0x315E2145: "user32.dll!GetDesktopWindow",
    0x006B8029: "ws2_32.dll!WSAStartup",
    0xE0DF0FEA: "ws2_32.dll!WSASocketA",
    0x6737DBC2: "ws2_32.dll!bind",
    0xFF38E9B7: "ws2_32.dll!listen",
    0xE13BEC74: "ws2_32.dll!accept",
    0x614D6E75: "ws2_32.dll!closesocket",
    0x6174A599: "ws2_32.dll!connect",
    0x5FC8D902: "ws2_32.dll!recv",
    0x5F38EBC2: "ws2_32.dll!send",
    0xA779563A: "wininet.dll!InternetOpenA",
    0xC69F8957: "wininet.dll!InternetConnectA",
    0x3B2E55EB: "wininet.dll!HttpOpenRequestA",
    0x7B18062D: "wininet.dll!HttpSendRequestA",
    0x0BE057B7: "wininet.dll!InternetErrorDlg",
    0xE2899612: "wininet.dll!InternetReadFile",
    0x869E4675: "wininet.dll!InternetSetOptionA",
}


# Matching code blocks will be named, depending on the proc flag.
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
}, {
    'name': 'decrypt_stub',
    'proc': False,
    'comment': """
Cobalt Strike x64 decryption stub, used to encapsulate Beacon
Following the stub is a 4 byte key and 4 byte length
Decryption is 4-byte XOR with plaintext feedback
""",
    'start': (
        0xEB, 0x33,                     # jmp        0x103a
        0x5D,                           # pop        rbp
        0x8B, 0x45, 0x00,               # mov        eax, dword [rbp]
        0x48, 0x83, 0xC5, 0x04,         # add        rbp, 0x4
        0x8B, 0x4D, 0x00,               # mov        ecx, dword [rbp]
        0x31, 0xC1,                     # xor        ecx, eax
        0x48, 0x83, 0xC5, 0x04,         # add        rbp, 0x4
        0x55,                           # push       rbp
        0x8B, 0x55, 0x00,               # mov        edx, dword [rbp]
        0x31, 0xC2,                     # xor        edx, eax
        0x89, 0x55, 0x00,               # mov        dword [rbp], edx
        0x31, 0xD0,                     # xor        eax, edx
        0x48, 0x83, 0xC5, 0x04,         # add        rbp, 0x4
        0x83, 0xE9, 0x04,               # sub        ecx, 0x4
        0x31, 0xD2,                     # xor        edx, edx
        0x39, 0xD1,                     # cmp        ecx, edx
        0x74, 0x02,                     # je         0x1032
        0xEB, 0xE7,                     # jmp        0x1019
        0x58,                           # pop        rax
        0xFC,                           # cld
        0x48, 0x83, 0xE4, 0xF0,         # and        rsp, 0xfffffffffffffff0
        0xFF, 0xD0,                     # call       rax
        0xE8, 0xC8, 0xFF, 0xFF, 0xFF,   # call       0x1007
    ),
    'offsets': (
        (0x3A+0, 'payload_key'),
        (0x3A+4, 'payload_size'),
        (0x3A+8, 'payload_data'),
    )
},
)


def hexaddr(addr):
    return "0x%x" % addr


def selection_is_single_instruction(seg, sel):
    typ = seg.getTypeAtAddress(sel[0])
    if not typ in (Segment.TYPE_CODE, Segment.TYPE_PROCEDURE):
        raise RuntimeError("Selection does not start with code!\n" +
                           "Try disassembling first.")
    ins = seg.getInstructionAtAddress(sel[0])
    return sel[1] == sel[0] + ins.getInstructionLength()


class InstructionReader:
    def __init__(self, seg, addr, size):
        self._seg = seg
        self._addr = addr
        self._size = size
        self._buf = seg.readBytes(addr, size)

    def yield_instructions(self, pos):
        while pos < self._addr + self._size:
            if self._seg.getTypeAtAddress(pos) not in (Segment.TYPE_CODE,
                                                       Segment.TYPE_PROCEDURE):
                pos += 1
                continue
            ins = self._seg.getInstructionAtAddress(pos)
            yield pos, ins
            pos += ins.getInstructionLength()

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

    def first_stack_instruction(self, pos, n=16):
        for addr, ins in self.yield_instructions(pos):
            op = ins.getInstructionString()
            if ins.isAConditionalJump() or ins.isAnInconditionalJump():
                break
            if op in ('hlt', 'int', 'enter', 'leave'):
                break
            if op.startswith('ret') or op.startswith('iret') or \
               op.startswith('sys'):
                break
            if op.startswith('push') or op.startswith('pop'):
                return addr, ins
            if addr > pos + n:
                break
        return None, None


def main():
    doc = Document.getCurrentDocument()
    seg = doc.getCurrentSegment()
    sel = doc.getSelectionAddressRange()

    print("===> Analyzing shellcode")
    if doc.is64Bits():
        print("64bit")
    else:
        print("32bit")

    ans = doc.message("Mark segment as undefined and disassemble?",
                      ['Cancel', 'No', 'Yes'])
    if ans == 0:
        return
    elif ans == 2:
        seg.markRangeAsUndefined(seg.getStartingAddress(), seg.getLength())
        seg.disassembleWholeSegment()

    if selection_is_single_instruction(seg, sel):
        print("operating on current segment")
        range_addr = seg.getStartingAddress()
        range_size = seg.getLength()
    else:
        print("operating on current selection")
        range_addr = sel[0]
        range_size = sel[1] - sel[0]

    print("analyzing range %s:%s" % (hexaddr(range_addr),
                                     hexaddr(range_addr + range_size)))

    reader = InstructionReader(seg, range_addr, range_size)

    # identify and mark known blocks
    for block, start_addr, end_addr in reader.yield_known_blocks():
        print("---> found known block '%s' at %s" % (block['name'],
                                                     hexaddr(start_addr)))
        name = "%s_%x" % (block['name'], start_addr)
        seg.setNameAtAddress(start_addr, name)
        if 'proc' in block and block['proc']:
            seg.markAsProcedure(start_addr)
        if 'comment' in block and block['comment']:
            seg.setCommentAtAddress(start_addr, block['comment'])
        if 'inline_comment' in block and block['inline_comment']:
            seg.setInlineCommentAtAddress(start_addr, block['inline_comment'])
        if 'offsets' in block:
            for offset, offset_name in block['offsets']:
                offset_addr = start_addr + offset
                offset_name = "%s_%x" % (offset_name, offset_addr)
                seg.setNameAtAddress(offset_addr, offset_name)

    # xref or annotate call, pop reg combo
    for addr, ins in reader.yield_instructions(range_addr):
        if ins.getInstructionString() != 'call':
            continue
        arg = ins.getRawArgument(0)
        if not arg.startswith('0x'):
            continue
        target_addr = int(arg, 16)
        stackop_addr, stackop_ins = reader.first_stack_instruction(target_addr)
        if stackop_ins == None or stackop_ins.getInstructionString() != 'pop':
            continue
        if seg.getNameAtAddress(target_addr) == None:
            seg.setNameAtAddress(target_addr,
                                 "pop_retaddr_%x" % target_addr)
        reg = stackop_ins.getRawArgument(0)
        print("---> found call + pop retaddr combo at %s -> %s" % (
            hexaddr(addr), hexaddr(target_addr)))
        loaded_addr = addr + ins.getInstructionLength()
        if loaded_addr == range_addr + range_size:
            # Hopper silently ignores xrefs to EOF
            seg.setInlineCommentAtAddress(stackop_addr, "end of shellcode")
        else:
            seg.addReference(stackop_addr, loaded_addr)

    # annotate known winapi hashes
    for addr, ins in reader.yield_instructions(range_addr):
        # x86 uses push, x64 uses movabs
        op = ins.getInstructionString()
        if not op in ('push', 'mov', 'movabs'):
            continue
        if op == 'push':
            argn = 0
        elif op == 'mov':
            argn = 1
        elif op == 'movabs':
            argn = 1
        arg = ins.getRawArgument(argn)
        if not arg.startswith('0x'):
            continue
        cand_hash = int(arg, 16)
        if cand_hash in DLL_FUNC_HASHES:
            name = DLL_FUNC_HASHES[cand_hash]
            seg.setInlineCommentAtAddress(addr, name)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        Document.getCurrentDocument().message(str(e), ['Ok'])
        traceback.print_exc()

