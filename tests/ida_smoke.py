"""Run with File > Script file in IDA after opening a test Mach-O.

Writes a JSON report and a text dump beside the temporary test input. It does
not run or attach to the input executable or modify its bytes or metadata.
"""
import hashlib
import json
from pathlib import Path
import sys

import ida_auto
import ida_bytes
import ida_fixup
import ida_kernwin
import ida_nalt
import ida_pro

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import ObjCExplore as oe

ida_auto.auto_wait()
dump = oe.ClassDump().parse()
input_path = Path(ida_nalt.get_input_file_path())
objects = dump.classes + dump.protocols + dump.categories
methods = [method for obj in objects for method in obj.methods]
report = {
    'input': str(input_path),
    'sha256': hashlib.sha256(input_path.read_bytes()).hexdigest(),
    'sdk': ida_pro.IDA_SDK_VERSION,
    'python': sys.version,
    'classes': len(dump.classes),
    'protocols': len(dump.protocols),
    'categories': len(dump.categories),
    'methods': len(methods),
    'class_methods': sum(len(obj.methods) for obj in dump.classes),
    'protocol_methods': sum(len(obj.methods) for obj in dump.protocols),
    'category_methods': sum(len(obj.methods) for obj in dump.categories),
    'properties': sum(len(obj.properties) for obj in objects),
    'ivars': sum(len(obj.ivars) for obj in dump.classes),
    'unknown_ivar_offsets': sum(iv.offset is None for obj in dump.classes for iv in obj.ivars),
    'diagnostics': dump.diagnostics,
    'cancelled': dump.cancelled,
    'class_names': [obj.name for obj in dump.classes],
    'protocol_names': [obj.name for obj in dump.protocols],
    'category_names': [obj.class_name + '(' + obj.name + ')' for obj in dump.categories],
    'unmapped_implementations': [hex(m.imp) for m in methods if m.imp and not ida_bytes.is_mapped(m.imp)],
    'fixups': [],
}
for name, start, end in dump.reader.segments():
    if name.rsplit(':', 1)[-1] == '__objc_classlist':
        for ea in range(start, min(end, start + 5 * dump.pointer_size), dump.pointer_size):
            target = dump.reader.pointer(ea)
            for slot in (ea, target, target + dump.pointer_size, target + 4 * dump.pointer_size):
                fd = ida_fixup.fixup_data_t()
                report['fixups'].append({
                    'ea': hex(slot),
                    'raw': hex(int.from_bytes(dump.reader.read(slot, dump.pointer_size), 'little')),
                    'resolved': hex(dump.reader.pointer(slot)),
                    'fixup': {'base': hex(fd.get_base()), 'off': hex(fd.off),
                              'displacement': fd.displacement} if fd.get(slot) else None,
                })
path = input_path.with_name(input_path.name + '.objc-report.json')
path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
with input_path.with_name(input_path.name + '.objc.txt').open('w', encoding='utf-8') as output:
    dump.write(output)
assert objects, 'Expected ObjC metadata in this smoke-test input'
assert not dump.cancelled, 'Smoke test was cancelled'
assert not report['unmapped_implementations'], 'Unresolved method implementations'
print('ObjCExplorer smoke report: %s' % path)
# Set OBJC_SMOKE_SHOW_GUI=False when exercising an already installed plugin.
if globals().get('OBJC_SMOKE_SHOW_GUI', True):
    # Retain the session for real GUI navigation/export/lifetime checks.
    explorer = oe.PLUGIN_ENTRY().init()
    assert explorer.run(0)
