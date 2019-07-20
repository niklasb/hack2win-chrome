## Hack2Win 2018 -- Chrome sandbox

This is a sandbox escape exploit for Chrome 69.0.3497.92 / Windows 1803 (up to date on Sep 21st 2018)

**Authors**: [Ned Williamson](https://twitter.com/NedWilliamson) (bug & exploit), 
[Niklas Baumstark](https://twitter.com/_niklasb) (exploit & plugging everything together)

Bug report/writeup: https://bugs.chromium.org/p/chromium/issues/detail?id=888926


### Building vulnerable Chrome & patching the renderer

It would be hard to reproduce the full-chain exploit because Chrome & Windows version have 
to match what we targetted back in September 2018. The files for the renderer patch
via DLL injection are just here for reference
(in `inject/`).

Instead you can build a vulnerable version of Chrome and apply custom renderer patches
to reproduce the sandbox escape as a standalone exploit:
In an existing Chromium source directory, do `git checkout 271eaf && gclient sync`, then rebuild.
To apply the renderer patches required for the standalone sandbox escape, do 
`patch -p1 < /path/to/renderer-271eaf.patch`.


### Running

`pwn.py` is the web server that serves the exploit. Run it on Linux (or WSL) and start
Chrome in guest mode, then browse to `http://localhost:8000/`

## License

This code is released under a BSD license specified in the file [`LICENSE`](https://github.com/niklasb/hack2win-chrome/blob/master/LICENSE)
