# Scripts for Hopper Disassembler

Copyright (C) 2018, [Daniel Roethlisberger](//daniel.roe.ch/).

## Synopsis

    make install
    # check Scripts menu in Hopper

## Description

Some of my Hopper scripts that are polished and general enough to be
potentially useful to others.  Each of them is self-contained and should run on
latest Hopper 4 on macOS and Linux.  Since Hopper still uses ancient legacy
Python 2 for scripting and the Hopper API is very far from pythonic, do not
expect beautiful code.

## Scripts

-   **Analyze Shellcode** - detect and annotate typical shellcode patterns:
    known code blocks, call import by hash, and call/pop reg
-   **Copy Selection As Python** - copy bytes in current selection to the
    clipboard, in python syntax, with assembly code in comments
-   **Copy Selection As Yara** - copy bytes in current selection to the
    clipboard, in yara syntax, with assembly code in comments
-   **File Offset Here** - add a prefix comment with the file offset at the
    current cursor position
-   **Fix Imports By Ordinal** - rename labels of imported functions by ordinal
    to their actual names

## Support

There is no support whatsoever.  No communication except in the form of pull
requests fixing bugs or adding features.  You are on your own.

## License

Source code provided under a 2-clause BSD license.

