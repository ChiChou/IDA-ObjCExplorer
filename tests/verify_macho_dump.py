#!/usr/bin/env python3
"""Compare an Objective-C dump with independent Apple tool metadata.

Standalone validation utility for thin, little-endian arm64e Mach-O samples
with relative Objective-C method lists, such as /usr/libexec/amfid and
/usr/libexec/rapportd. Requires Python 3, macOS otool, and dyld_info on PATH.
It does not import the project parser, require IDA, or execute the input binary.

Only each top-level object's own lists are counted; repeated descriptor
addresses are deduplicated. Selector references are resolved from otool's
selrefs table. Because otool can mislabel newer chained ivar pointers and omit
protocol class properties, those fields are checked through dyld_info -fixups
and file-backed bytes using the published objc4 layout. No raw chain format is
decoded. Other architectures and metadata formats are outside this utility's
scope. A supplied report/dump mismatch produces a nonzero exit status.

Examples:
  python3 tests/verify_macho_dump.py /usr/libexec/amfid
  python3 tests/verify_macho_dump.py /usr/libexec/rapportd \\
      --report rapportd.objc-report.json --dump rapportd.objc.txt \\
      --output rapportd-verified.json
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from collections import Counter


class FileImage:
    def __init__(self, binary, sections):
        self.data = Path(binary).read_bytes()
        assert self.data[:4] == b'\xcf\xfa\xed\xfe', 'Verifier expects a thin little-endian 64-bit Mach-O'
        self.sections = sections
        output = subprocess.check_output(['dyld_info', '-fixups', binary], text=True)
        self.fixups = {int(m.group(1), 16): int(m.group(2), 16) for m in re.finditer(
            r'^\s+\S+\s+\S+\s+(0x[0-9A-Fa-f]+)\s+(?:auth-)?rebase\s+(0x[0-9A-Fa-f]+)', output, re.M)}

    def read(self, ea, size):
        for _, _, start, length, offset in self.sections:
            if offset and start <= ea and ea + size <= start + length:
                at = offset + ea - start
                result = self.data[at:at + size]
                if len(result) == size:
                    return result
        raise ValueError('No file bytes at 0x%X' % ea)

    def uint(self, ea, size=4, signed=False):
        return int.from_bytes(self.read(ea, size), 'little', signed=signed)

    def pointer(self, ea):
        return self.fixups[ea] if ea in self.fixups else self.uint(ea, 8)

    def string(self, ea):
        if not ea:
            return ''
        data = bytearray()
        for at in range(ea, ea + 65536):
            byte = self.read(at, 1)[0]
            if not byte:
                return data.decode('utf-8')
            data.append(byte)
        raise ValueError('Unterminated string at 0x%X' % ea)


def inspect(binary):
    text = subprocess.check_output(['otool', '-arch', 'arm64e', '-ov', binary], text=True)
    load = subprocess.check_output(['otool', '-arch', 'arm64e', '-l', binary], text=True)
    sections = []
    for match in re.finditer(
            r'\s+sectname (\S+)\n\s+segname (\S+)\n\s+addr (0x[0-9a-f]+)'
            r'\n\s+size (0x[0-9a-f]+)\n\s+offset (\d+)', load):
        section, segment, address, size, offset = match.groups()
        sections.append((section, segment, int(address, 16), int(size, 16), int(offset)))
    selref_start = next(a for s, _, a, _, _ in sections if s == '__objc_selrefs')
    seltext = text.split('Contents of (__DATA,__objc_selrefs) section\n')[1].split('Contents of')[0]
    selectors = {selref_start + i * 8: (int(m.group(1), 16), m.group(2)) for i, m in enumerate(
        re.finditer(r'^\s+(0x[0-9a-f]+) (.*)$', seltext, re.M))}
    objects = []
    section = obj = context = None
    meta = False
    method, prop, ivar = {}, {}, {}
    method_fields = ('baseMethods', 'instanceMethods', 'classMethods',
                     'optionalInstanceMethods', 'optionalClassMethods')
    property_fields = ('baseProperties', 'instanceProperties')
    for line in text.splitlines():
        if line.startswith('Contents of'):
            section, obj = line, None
            continue
        kind = ('class' if '__objc_classlist' in (section or '') else
                'protocol' if '__objc_protolist' in (section or '') else
                'category' if '__objc_catlist' in (section or '') else None)
        if kind is None:
            continue
        if re.match(r'^[0-9a-f]+ 0x', line):
            obj = dict(kind=kind, name='', class_name='', ea=int(line.split()[1], 16),
                       methods=[], properties=[], ivars=[], declared_methods=0)
            objects.append(obj)
            meta, context = False, None
            continue
        if obj is None:
            continue
        if line == 'Meta Class':
            meta, context = True, None
            continue
        indent, value = len(line) - len(line.lstrip()), line.strip()
        own = 8 if kind == 'class' else 4
        if indent == own:
            match = re.match(r'name\s+0x[0-9a-f]+ (.+)$', value)
            if match:
                obj['name'] = match.group(1)
            match = re.match(r'cls\s+0x[0-9a-f]+ _OBJC_CLASS_\$_(.*)$', value)
            if match:
                obj['class_name'] = match.group(1)
            field = value.split()[0] if value else ''
            context = field if field in method_fields + property_fields + ('ivars',) else None
        if indent != own + 4 or not context:
            continue
        if context in method_fields:
            match = re.match(r'count\s+(\d+)$', value)
            if match:
                obj['declared_methods'] += int(match.group(1))
            match = re.match(r'name\s+0x[0-9a-f]+ \((0x[0-9a-f]+)\)', value)
            if match:
                ref = int(match.group(1), 16)
                target, selector = selectors[ref]
                method = dict(name=selector, selector_ea=target, selector_ref=ref,
                              is_class=meta if kind == 'class' else context in ('classMethods', 'optionalClassMethods'),
                              optional=context.startswith('optional'))
            match = re.match(r'types\s+0x[0-9a-f]+ \((0x[0-9a-f]+)\) (.*)$', value)
            if match:
                method['types'], method['types_ea'] = match.group(2), int(match.group(1), 16)
            if value.startswith('imp '):
                match = re.search(r'\((0x[0-9a-f]+)\)', value)
                method['imp'] = int(match.group(1), 16) if match else 0
                assert 'name' in method and 'types' in method, 'Unsupported otool method representation'
                obj['methods'].append(method)
                method = {}
        elif context in property_fields:
            match = re.match(r'name\s+0x[0-9a-f]+ (.*)$', value)
            if match:
                prop = dict(name=match.group(1), is_class=meta if kind == 'class' else False)
            match = re.match(r'attributes\s+0x[0-9a-f]+ (.*)$', value)
            if match:
                prop['attributes'] = match.group(1)
                obj['properties'].append(prop)
                prop = {}
        else:
            match = re.match(r'offset\s+(0x[0-9a-f]+)(?: (-?\d+))?(?: .*)?$', value)
            if match:
                ivar = dict(offset_ea=int(match.group(1), 16), offset=int(match.group(2)) if match.group(2) else None)
            match = re.match(r'name\s+0x[0-9a-f]+(?: (.*))?$', value)
            if match:
                ivar['name'] = match.group(1) or ''
            match = re.match(r'type\s+0x[0-9a-f]+(?: (.*))?$', value)
            if match:
                ivar['types'] = match.group(1) or ''
            if value.startswith('size '):
                ivar['size'] = int(value.split()[1])
                assert 'offset' in ivar and 'name' in ivar, repr((obj['name'], value, ivar))
                obj['ivars'].append(ivar)
                ivar = {}
    assert all(o['declared_methods'] == len(o['methods']) for o in objects)
    raw_counts = Counter(o['kind'] for o in objects)
    unique = {}
    for obj in objects:
        key = obj['kind'], obj['ea']
        if key in unique:
            assert obj == unique[key], 'Repeated descriptor has different otool output'
        else:
            unique[key] = obj
    objects = list(unique.values())
    file_image = FileImage(binary, sections)
    ivar_label_differences = []
    extra_class_properties = []
    for obj in objects:
        if obj['kind'] == 'class':
            ro = file_image.pointer(obj['ea'] + 32) & 0x00007FFFFFFFFFF8
            ivar_list = file_image.pointer(ro + 48)
            if ivar_list:
                stride, count = file_image.uint(ivar_list), file_image.uint(ivar_list + 4)
                assert count == len(obj['ivars'])
                for index, ivar in enumerate(obj['ivars']):
                    entry = ivar_list + 8 + index * stride
                    offset_ea = file_image.pointer(entry)
                    name = file_image.string(file_image.pointer(entry + 8))
                    types = file_image.string(file_image.pointer(entry + 16))
                    try:
                        offset = file_image.uint(offset_ea, signed=True) if offset_ea else None
                    except ValueError:
                        offset = None
                    old = (ivar['name'], ivar['types'], ivar['offset'])
                    new = (name, types, offset)
                    if old != new:
                        ivar_label_differences.append({'entry': hex(entry), 'otool': old, 'dyld_info_and_file': new})
                    ivar.update(name=name, types=types, offset=offset, offset_ea=offset_ea)
        elif obj['kind'] == 'protocol':
            # protocol_t.size gates the tail; classProperties sits at +88 on 64-bit.
            if file_image.uint(obj['ea'] + 64) < 96:
                continue
            props = file_image.pointer(obj['ea'] + 88)
            if not props:
                continue
            stride, count = file_image.uint(props), file_image.uint(props + 4)
            for index in range(count):
                entry = props + 8 + index * stride
                prop = dict(name=file_image.string(file_image.pointer(entry)),
                            attributes=file_image.string(file_image.pointer(entry + 8)), is_class=True)
                obj['properties'].append(prop)
                extra_class_properties.append({'protocol': obj['name'], **prop})
    notes = dict(raw_section_reference_counts=dict(raw_counts),
                 unique_descriptor_counts=dict(Counter(o['kind'] for o in objects)),
                 otool_ivar_label_differences=len(ivar_label_differences),
                 otool_ivar_difference_fields={field: sum(d['otool'][i] != d['dyld_info_and_file'][i]
                       for d in ivar_label_differences) for i, field in enumerate(('name', 'types', 'offset'))},
                 otool_ivar_difference_examples=ivar_label_differences[:3],
                 protocol_class_properties_omitted_by_otool=extra_class_properties)
    return objects, sections, notes


def owner(obj):
    return '%s (%s)' % (obj['class_name'], obj['name']) if obj['kind'] == 'category' else obj['name']


def summary(binary, objects, sections):
    out = {'sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest()}
    for kind in ('class', 'protocol', 'category'):
        out[{'class': 'classes', 'protocol': 'protocols', 'category': 'categories'}[kind]] = sum(o['kind'] == kind for o in objects)
        out[kind + '_methods'] = sum(len(o['methods']) for o in objects if o['kind'] == kind)
        out[kind + '_names'] = [(o['class_name'] + '(' + o['name'] + ')') if kind == 'category' else o['name']
                               for o in objects if o['kind'] == kind]
    for field in ('methods', 'properties', 'ivars'):
        out[field] = sum(len(o[field]) for o in objects)
    out['unknown_ivar_offsets'] = sum(i['offset'] is None for o in objects for i in o['ivars'])
    out['unmapped_implementations'] = [hex(m['imp']) for o in objects for m in o['methods'] if m['imp'] and
        not any(a <= m['imp'] < a + size and offset for _, _, a, size, offset in sections)]
    return out


def compare_dump(path, objects):
    methods, properties, ivars = [], [], []
    kind, name, optional = None, None, False
    for line in Path(path).read_text().splitlines():
        match = re.match(r'@interface (\S+) \(([^)]+)\)', line)
        if match:
            kind, name, optional = 'category', '%s (%s)' % match.groups(), False
        elif line.startswith('@interface '):
            kind, name, optional = 'class', line.split()[1], False
        elif line.startswith('@protocol '):
            kind, name, optional = 'protocol', line.split()[1], False
        elif line in ('@optional', '@required'):
            optional = line == '@optional'
        match = re.match(r'  ([+-]) (.*?) // (.*?)(?: @ (0x[0-9A-F]+))?$', line)
        if match:
            sign, selector, types, imp = match.groups()
            methods.append((kind, name, sign == '+', optional, selector, types, int(imp, 16) if imp else 0))
        match = re.match(r'  property (\+ )?(.*?) // (.*)$', line)
        if match:
            properties.append((kind, name, bool(match.group(1)), match.group(2), match.group(3)))
        match = re.match(r'  ivar (.*?) // (.*), offset (None|-?\d+)$', line)
        if match:
            ivars.append((kind, name, match.group(1), match.group(2), None if match.group(3) == 'None' else int(match.group(3))))
    expected_methods = [(o['kind'], owner(o), m['is_class'], m['optional'], m['name'], m['types'], m['imp'])
                        for o in objects for m in o['methods']]
    expected_properties = [(o['kind'], owner(o), p['is_class'], p['name'], p['attributes']) for o in objects for p in o['properties']]
    expected_ivars = [(o['kind'], owner(o), i['name'], i['types'], i['offset']) for o in objects for i in o['ivars']]
    return {field: {'rows': len(actual), 'exact_match': sorted(actual) == sorted(expected),
                    'only_export': list((Counter(actual) - Counter(expected)).elements()),
                    'only_otool': list((Counter(expected) - Counter(actual)).elements())}
            for field, actual, expected in (('methods', methods, expected_methods),
                                           ('properties', properties, expected_properties),
                                           ('ivars', ivars, expected_ivars))}


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('binary', help='thin arm64e Mach-O file to inspect without executing')
    parser.add_argument('--report', help='optional plugin validation JSON report to compare')
    parser.add_argument('--dump', help='optional raw-encoding text export to compare exactly')
    parser.add_argument('--output', help='write verification JSON to this path (default: stdout)')
    args = parser.parse_args()
    objects, sections, notes = inspect(args.binary)
    output = summary(args.binary, objects, sections)
    if args.report:
        report = json.loads(Path(args.report).read_text())
        output['report_mismatches'] = {k: {'report': report[k], 'otool': v} for k, v in output.items() if k in report and report[k] != v}
    if args.dump:
        output['export_comparison'] = compare_dump(args.dump, objects)
    output['verification_notes'] = notes
    output['selector_examples'] = [dict(owner=owner(o), selector=m['name'], selector_ref=hex(m['selector_ref']),
        selector_address=hex(m['selector_ea']), types_address=hex(m['types_ea']), imp=hex(m['imp']))
        for o in objects for m in o['methods']][:3]
    encoded = json.dumps(output, indent=2) + '\n'
    if args.output:
        Path(args.output).write_text(encoded)
        print(args.output)
    else:
        print(encoded, end='')
    if output.get('report_mismatches') or any(not c['exact_match'] for c in output.get('export_comparison', {}).values()):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
