# vim: set fileencoding=utf-8 :

# «Fix Imports By Ordinal» for Hopper 4
# Copyright (c) 2018, Daniel Roethlisberger <daniel@roe.ch>
# https://github.com/droe/hopper-scripts
#
# Rename imports by ordinal to their actual names.
#
# Unfortunately, Hopper does not currently allow full-featured access to
# external definitions from scripts.  Best we can do is rename the labels, but
# that will result in a different user experience than if the import would have
# been handled by Hopper by name.


import traceback
import re


IMPORTS = {
    'ws2_32.dll': {
        1: 'accept',
        2: 'bind',
        3: 'closesocket',
        4: 'connect',
        5: 'getpeername',
        6: 'getsockname',
        7: 'getsockopt',
        8: 'htonl',
        9: 'htons',
        10: 'ioctlsocket',
        11: 'inet_addr',
        12: 'inet_ntoa',
        13: 'listen',
        14: 'ntohl',
        15: 'ntohs',
        16: 'recv',
        17: 'recvfrom',
        18: 'select',
        19: 'send',
        20: 'sendto',
        21: 'setsockopt',
        22: 'shutdown',
        23: 'socket',
        24: 'WSApSetPostRoutine',
        25: 'FreeAddrInfoEx',
        26: 'FreeAddrInfoExW',
        27: 'FreeAddrInfoW',
        28: 'GetAddrInfoExA',
        29: 'GetAddrInfoExCancel',
        30: 'GetAddrInfoExOverlappedResult',
        31: 'GetAddrInfoExW',
        32: 'GetAddrInfoW',
        33: 'GetHostNameW',
        34: 'GetNameInfoW',
        35: 'InetNtopW',
        36: 'InetPtonW',
        37: 'SetAddrInfoExA',
        38: 'SetAddrInfoExW',
        39: 'WPUCompleteOverlappedRequest',
        40: 'WPUGetProviderPathEx',
        41: 'WSAAccept',
        42: 'WSAAddressToStringA',
        43: 'WSAAddressToStringW',
        44: 'WSAAdvertiseProvider',
        45: 'WSACloseEvent',
        46: 'WSAConnect',
        47: 'WSAConnectByList',
        48: 'WSAConnectByNameA',
        49: 'WSAConnectByNameW',
        50: 'WSACreateEvent',
        51: 'gethostbyaddr',
        52: 'gethostbyname',
        53: 'getprotobyname',
        54: 'getprotobynumber',
        55: 'getservbyname',
        56: 'getservbyport',
        57: 'gethostname',
        58: 'WSADuplicateSocketA',
        59: 'WSADuplicateSocketW',
        60: 'WSAEnumNameSpaceProvidersA',
        61: 'WSAEnumNameSpaceProvidersExA',
        62: 'WSAEnumNameSpaceProvidersExW',
        63: 'WSAEnumNameSpaceProvidersW',
        64: 'WSAEnumNetworkEvents',
        65: 'WSAEnumProtocolsA',
        66: 'WSAEnumProtocolsW',
        67: 'WSAEventSelect',
        68: 'WSAGetOverlappedResult',
        69: 'WSAGetQOSByName',
        70: 'WSAGetServiceClassInfoA',
        71: 'WSAGetServiceClassInfoW',
        72: 'WSAGetServiceClassNameByClassIdA',
        73: 'WSAGetServiceClassNameByClassIdW',
        74: 'WSAHtonl',
        75: 'WSAHtons',
        76: 'WSAInstallServiceClassA',
        77: 'WSAInstallServiceClassW',
        78: 'WSAIoctl',
        79: 'WSAJoinLeaf',
        80: 'WSALookupServiceBeginA',
        81: 'WSALookupServiceBeginW',
        82: 'WSALookupServiceEnd',
        83: 'WSALookupServiceNextA',
        84: 'WSALookupServiceNextW',
        85: 'WSANSPIoctl',
        86: 'WSANtohl',
        87: 'WSANtohs',
        88: 'WSAPoll',
        89: 'WSAProviderCompleteAsyncCall',
        90: 'WSAProviderConfigChange',
        91: 'WSARecv',
        92: 'WSARecvDisconnect',
        93: 'WSARecvFrom',
        94: 'WSARemoveServiceClass',
        95: 'WSAResetEvent',
        96: 'WSASend',
        97: 'WSASendDisconnect',
        98: 'WSASendMsg',
        99: 'WSASendTo',
        100: 'WSASetEvent',
        101: 'WSAAsyncSelect',
        102: 'WSAAsyncGetHostByAddr',
        103: 'WSAAsyncGetHostByName',
        104: 'WSAAsyncGetProtoByNumber',
        105: 'WSAAsyncGetProtoByName',
        106: 'WSAAsyncGetServByPort',
        107: 'WSAAsyncGetServByName',
        108: 'WSACancelAsyncRequest',
        109: 'WSASetBlockingHook',
        110: 'WSAUnhookBlockingHook',
        111: 'WSAGetLastError',
        112: 'WSASetLastError',
        113: 'WSACancelBlockingCall',
        114: 'WSAIsBlocking',
        115: 'WSAStartup',
        116: 'WSACleanup',
        117: 'WSASetServiceA',
        118: 'WSASetServiceW',
        119: 'WSASocketA',
        120: 'WSASocketW',
        121: 'WSAStringToAddressA',
        122: 'WSAStringToAddressW',
        123: 'WSAUnadvertiseProvider',
        124: 'WSAWaitForMultipleEvents',
        125: 'WSCDeinstallProvider',
        126: 'WSCDeinstallProvider32',
        127: 'WSCDeinstallProviderEx',
        128: 'WSCEnableNSProvider',
        129: 'WSCEnableNSProvider32',
        130: 'WSCEnumNameSpaceProviders32',
        131: 'WSCEnumNameSpaceProvidersEx32',
        132: 'WSCEnumProtocols',
        133: 'WSCEnumProtocols32',
        134: 'WSCEnumProtocolsEx',
        135: 'WSCGetApplicationCategory',
        136: 'WSCGetApplicationCategoryEx',
        137: 'WSCGetProviderInfo',
        138: 'WSCGetProviderInfo32',
        139: 'WSCGetProviderPath',
        140: 'WSCGetProviderPath32',
        141: 'WSCInstallNameSpace',
        142: 'WSCInstallNameSpace32',
        143: 'WSCInstallNameSpaceEx',
        144: 'WSCInstallNameSpaceEx2',
        145: 'WSCInstallNameSpaceEx32',
        146: 'WSCInstallProvider',
        147: 'WSCInstallProvider64_32',
        148: 'WSCInstallProviderAndChains64_32',
        149: 'WSCInstallProviderEx',
        150: 'WSCSetApplicationCategory',
        151: '__WSAFDIsSet',
        152: 'WSCSetApplicationCategoryEx',
        153: 'WSCSetProviderInfo',
        154: 'WSCSetProviderInfo32',
        155: 'WSCUnInstallNameSpace',
        156: 'WSCUnInstallNameSpace32',
        157: 'WSCUnInstallNameSpaceEx2',
        158: 'WSCUpdateProvider',
        159: 'WSCUpdateProvider32',
        160: 'WSCUpdateProviderEx',
        161: 'WSCWriteNameSpaceOrder',
        162: 'WSCWriteNameSpaceOrder32',
        163: 'WSCWriteProviderOrder',
        164: 'WSCWriteProviderOrder32',
        165: 'WSCWriteProviderOrderEx',
        166: 'WahCloseApcHelper',
        167: 'WahCloseHandleHelper',
        168: 'WahCloseNotificationHandleHelper',
        169: 'WahCloseSocketHandle',
        170: 'WahCloseThread',
        171: 'WahCompleteRequest',
        172: 'WahCreateHandleContextTable',
        173: 'WahCreateNotificationHandle',
        174: 'WahCreateSocketHandle',
        175: 'WahDestroyHandleContextTable',
        176: 'WahDisableNonIFSHandleSupport',
        177: 'WahEnableNonIFSHandleSupport',
        178: 'WahEnumerateHandleContexts',
        179: 'WahInsertHandleContext',
        180: 'WahNotifyAllProcesses',
        181: 'WahOpenApcHelper',
        182: 'WahOpenCurrentThread',
        183: 'WahOpenHandleHelper',
        184: 'WahOpenNotificationHandleHelper',
        185: 'WahQueueUserApc',
        186: 'WahReferenceContextByHandle',
        187: 'WahRemoveHandleContext',
        188: 'WahWaitForNotification',
        189: 'WahWriteLSPEvent',
        190: 'freeaddrinfo',
        191: 'getaddrinfo',
        192: 'getnameinfo',
        193: 'inet_ntop',
        194: 'inet_pton',
        500: 'WEP',
    },
}


def hexaddr(addr):
    return "0x%x" % addr


def selection_is_single_instruction(doc, seg, sel):
    typ = seg.getTypeAtAddress(sel[0])
    #if typ in (Segment.TYPE_EXTERN,):
    if typ in (61,):
        if doc.is64Bits():
            return sel[1] == sel[0] + 8
        else:
            return sel[1] == sel[0] + 4
    if typ in (Segment.TYPE_CODE, Segment.TYPE_PROCEDURE):
        ins = seg.getInstructionAtAddress(sel[0])
        return sel[1] == sel[0] + ins.getInstructionLength()
    raise RuntimeError("Selection starts with unhandled type %s (%i)" % ( \
                       seg.stringForType(typ), typ))


def main():
    doc = Document.getCurrentDocument()
    seg = doc.getCurrentSegment()
    sel = doc.getSelectionAddressRange()

    print("===> Walking current segment or selection")

    if selection_is_single_instruction(doc, seg, sel):
        print("operating on current segment")
        range_addr = seg.getStartingAddress()
        range_size = seg.getLength()
    else:
        print("operating on current selection")
        range_addr = sel[0]
        range_size = sel[1] - sel[0]

    print("analyzing range %s:%s" % (hexaddr(range_addr),
                                     hexaddr(range_addr + range_size)))


    pattern = re.compile(r'(imp|j)_ordinal_([A-Za-z0-9_]+).[Dd][Ll][Ll]_([0-9]+)')
    for addr in range(range_addr, range_addr + range_size):
        name = doc.getNameAtAddress(addr)
        if name == None:
            continue
        m = pattern.match(name)
        if not m:
            continue
        prefix = m.group(1) + '_'
        libname = m.group(2).lower() + '.dll'
        ordinal = int(m.group(3))
        if libname in IMPORTS and ordinal in IMPORTS[libname]:
            symname = prefix + IMPORTS[libname][ordinal]
            print("renaming %s %s to %s" % (hexaddr(addr), name, symname))
            doc.setNameAtAddress(addr, symname)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        Document.getCurrentDocument().message(str(e), ['Ok'])
        traceback.print_exc()

