# ObjCExplorer for IDA Pro

Browse Objective-C classes, protocols, categories, methods, properties and ivars
in a loaded Mach-O image. Open a class, protocol or category to inspect its
members, then double-click a method to jump to its implementation. Protocol
declarations without an implementation jump to their metadata.

## Installation

Requires IDA 9.x with Python 3. The GUI uses native IDA chooser controls and
does not require PyQt5 or PySide6. Copy `ObjCExplore.py` and the complete
`objc_explorer` directory into your IDA user `plugins` directory, preserving
this layout:

```text
plugins/
├── ObjCExplore.py
└── objc_explorer/
    ├── __init__.py
    ├── ida_reader.py
    └── runtime.py
```

Keep the helper modules inside `objc_explorer`; IDA treats Python files placed
directly in `plugins` as plugin entry points.

Restart IDA, load a binary, and press **Ctrl + Shift + E** (or select
**Edit → Plugins → ObjCExplorer**). For development, run `ObjCExplore.py` using
**File → Script file** without installing it.

Use the browser's **Export dump…** context-menu action to save a UTF-8 inspection
dump. It includes raw type encodings, properties, ivars and diagnostics; it is
not a compilable header.
Existing destinations are replaced after IDA's save dialog confirms them.

## Runtime support

- Absolute and relative method entries, declared entry sizes, signed relative
  pointers, indirect selectors and direct selectors.
- Modern dyld shared selector/type buffers and preattached category lists.
- Instance/class methods and all required/optional protocol method lists.
- Class data flags, categories, properties and ivars; 32- and 64-bit layouts.
- Module-prefixed shared-cache section names, partial-image diagnostics,
  bounded reads and cancellation.

The adapter uses IDA's loader fixups for rebases, binds and authenticated
pointers. Load the Mach-O or dyld cache with the appropriate IDA loader first.
The plugin does not decode raw on-disk chained fixups or load missing cache
images. Modern cache selector buffers must be mapped, with the cache header or
supported `__objc_opt_ro` metadata available. Unsupported or missing metadata
produces diagnostics and partial results. Realized live `class_rw_t` structures
and native Swift reflection metadata are not yet supported.

## Validation

Run the standalone parser and IDA-adapter fixture tests:

```sh
python3 -m unittest discover -s tests -v
```

GUI validation details and tested sample versions are recorded in
[docs/validation.md](docs/validation.md). Cache layouts and 32-bit layouts have
synthetic fixtures; those fixtures are not a substitute for real cache testing.

ABI references: [Apple objc4](https://github.com/apple-oss-distributions/objc4),
[Apple dyld's ObjC visitor](https://github.com/apple-oss-distributions/dyld/blob/main/common/ObjCVisitor.cpp),
[IDAPython SDK](https://python.docs.hex-rays.com/).

Thanks to [trailofbits/ObjCGraphView](https://github.com/trailofbits/ObjCGraphView).
