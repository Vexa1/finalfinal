#!/usr/bin/env python3
"""Exit 1 if a Mach-O binary binds a symbol the macOS 10.15 SDK does not export, or declares a minimum
macOS above 10.15. Usage: symcheck.py SDK_TARBALL_OR_DIR BINARY..."""
import glob, os, re, sys
import lief

sdk, bins = sys.argv[1], sys.argv[2:]
exports = set()


def read_tbd(text):
    for m in re.finditer(r"(symbols|weak-symbols|objc-classes|objc-eh-types|objc-ivars|thread-local-symbols):\s*\[(.*?)\]", text, re.S):
        kind = m.group(1)
        for s in re.split(r"[\s,]+", m.group(2)):
            s = s.strip("'\" ")
            if not s:
                continue
            if kind == "objc-classes":
                exports.update(("_OBJC_CLASS_$_" + s, "_OBJC_METACLASS_$_" + s))
            elif kind == "objc-ivars":
                exports.add("_OBJC_IVAR_$_" + s)
            elif kind == "objc-eh-types":
                exports.add("_OBJC_EHTYPE_$_" + s)
            else:
                exports.add(s)


if os.path.isfile(sdk):
    # The SDK tarball itself (MacOSX10.15.sdk.tar.xz), read in place: no tar program, no extraction.
    import tarfile
    with tarfile.open(sdk, "r:xz") as tar:
        for member in tar:
            if member.isfile() and member.name.endswith(".tbd") and (
                "/System/Library/Frameworks/" in member.name or "/usr/lib/" in member.name
            ):
                read_tbd(tar.extractfile(member).read().decode("utf-8", "ignore"))
else:
    for f in glob.glob(os.path.join(sdk, "**", "*.tbd"), recursive=True):
        if os.path.isfile(f):
            read_tbd(open(f, errors="ignore").read())
if len(exports) < 100000:
    sys.exit(f"only {len(exports)} SDK symbols read: the SDK stubs did not extract")
print(f"{len(exports)} symbols exported by the macOS 10.15 SDK")
bad = False
for path in bins:
    b = lief.parse(path)
    if b is None:
        print(f"{path}: not a Mach-O file"); bad = True; continue
    bv = b.build_version
    minos = tuple(bv.minos) if bv else tuple(b.version_min.version)
    syms = sorted({x.symbol.name for x in b.bindings if x.symbol and x.symbol.name})
    missing = [s for s in syms if s not in exports]
    libs = [l.name for l in b.libraries if "UniformTypeIdentifiers" in l.name or "ScreenCaptureKit" in l.name]
    print(f"{os.path.basename(path)}: minimum macOS {'.'.join(map(str, minos))}, {len(syms)} bound symbols, {len(missing)} missing on 10.15")
    for m in missing:
        print("   missing:", m)
    for l in libs:
        print("   links a framework 10.15 lacks:", l)
    if missing or libs or minos > (10, 15, 0):
        bad = True
sys.exit(1 if bad else 0)
