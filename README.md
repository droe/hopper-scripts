# Scripts for Hopper Disassembler

Copyright (C) 2018, [Daniel Roethlisberger](//daniel.roe.ch/).

## Synopsis

    make install
    # check Scripts menu in Hopper

## Description

Some of my Hopper scripts that are polished and general enough to be
potentially useful to others.  They should run on latest Hopper 4 on macOS and
Linux.

The scripts use a nicer wrapper API around the strictly procedural Hopper
python API, otherwise the scripts are self-contained.

## Scripts

-   **Analyze Shellcode** - detect and annotate typical shellcode patterns:
    known code blocks, call import by hash, and call/pop reg
-   **Annotate Stack Strings in Selection** - annotate plaintext and
    XOR-encrypted stack strings
-   **Annotate Yara Matches** - apply a set of yara rules to the currently
    loaded document and annotate a summary of matching rules as well as each
    string occurence for matching rules
-   **Copy Selection As Python** - copy bytes in current selection to the
    clipboard, in python syntax, with assembly code in comments
-   **Copy Selection As Yara** - copy bytes in current selection to the
    clipboard, in yara syntax, with assembly code in comments
-   **File Offset Here** - add a prefix comment with the file offset at the
    current cursor position
-   **Fix Imports By Ordinal** - rename labels of imported functions by ordinal
    to their actual names
-   **Save Bytes From Here** - carve and save an arbitrarily-sized blob of
    optionally XOR-decrypted bytes from the current cursor position to a file

## Support

There is no support whatsoever.  No communication except in the form of pull
requests fixing bugs or adding features.  You are on your own.

## License

Source code provided under a 2-clause BSD license.

