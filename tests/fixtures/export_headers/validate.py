#!/usr/bin/env python3
"""Compile-check exported declarations against a project-owned runtime fixture.

Requires macOS and Xcode/Command Line Tools. Builds and runs only Fixture.m,
then compiles the generated header for arm64 and x86_64. No IDA is required.

Run from any directory:
  python3 tests/fixtures/export_headers/validate.py --output-dir /tmp/objc-headers
"""

import argparse
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from objc_explorer.runtime import Method, Property, Ivar, ObjCClass, ObjCProtocol, ObjCCategory


def model(records):
    """Adapt independently obtained runtime records to the exporter's input."""
    next_address = 0x1000

    def address():
        nonlocal next_address
        next_address += 0x10
        return next_address

    def members(record):
        return dict(
            methods=[Method(value['name'], value['types'], 0, address(),
                            value['is_class'], value['optional'])
                     for value in record['methods']],
            properties=[Property(value['name'], value['attributes'], address(),
                                 value['is_class']) for value in record['properties']],
            protocols=record['protocols'])

    classes = [ObjCClass(record['name'], address(), **members(record),
                         superclass=record['superclass'],
                         ivars=[Ivar(value['name'], value['types'], address(), value['offset'])
                                for value in record['ivars']])
               for record in records['classes']]
    protocols = [ObjCProtocol(record['name'], address(), **members(record))
                 for record in records['protocols']]
    categories = [ObjCCategory(record['name'], address(), **members(record),
                               class_name=record['class_name'])
                  for record in records['categories']]
    return SimpleNamespace(classes=classes, protocols=protocols, categories=categories,
                           diagnostics=[], cancelled=False)


def check_retained_declarations(header):
    # A header that comments out everything can compile, so also require the
    # supported declarations and dependencies to survive outside comments.
    source = re.sub(r'/\*.*?\*/|//[^\n]*', '', header, flags=re.S)
    required = {
        'superclass dependency': r'@interface\s+EXChild\s*:\s*EXZetaBase',
        'protocol dependency': r'@protocol\s+EXReadable\s*<\s*EXZetaProtocol\s*>',
        'category base': r'@interface\s+EXChild\s*\(\s*Extras\s*\)',
        'integer method': r'-\s*\([^)]*\)\s*count\s*;',
        'record method': r'translatePoint\s*:',
        'pointer-to-array argument': r'fillNumbers\s*:',
        'class method': r'\+\s*\([^)]*\)\s*relatedClass\s*;',
        'protocol optionality': r'@optional',
        'class property': r'@property\s*\([^)]*\bclass\b[^)]*\)[^;]*\bcapacity\s*;',
        'object protocol qualification': r'id\s*<\s*EXReadable\s*>[^;]*\bdelegate\s*;',
        'custom getter': r'getter\s*=\s*displayName',
        'custom setter': r'setter\s*=\s*updateDisplayName:',
    }
    missing = [name for name, pattern in required.items() if re.search(pattern, source) is None]
    if missing:
        raise AssertionError('Supported declarations missing from header: ' + ', '.join(missing))
    if 'consumeBlock:' not in header or 'consumeBlock' in source:
        raise AssertionError('Unknown block signature must survive as a comment, not a guessed declaration')
    point = re.search(r'-\s*\(([^)]+)\)\s*translatePoint\s*:', source)
    point_type = point.group(1).strip()
    if re.fullmatch(r'(?:struct\s+)?[A-Za-z_][A-Za-z0-9_]*', point_type) is None:
        raise AssertionError('Expected a named record type for translatePoint:')
    # Generated record tags may intentionally differ from the source tag to
    # avoid collisions with declarations already provided by an Apple SDK.
    return point_type


def validate(output_dir):
    from objc_explorer.headers import render_header

    output_dir.mkdir(parents=True, exist_ok=True)
    fixture = Path(__file__).with_name('Fixture.m')
    executable = output_dir / 'fixture'
    subprocess.run(['xcrun', 'clang', '-fobjc-arc', '-framework', 'Foundation',
                    str(fixture), '-o', str(executable)], check=True)
    captured = subprocess.check_output([str(executable)], text=True)
    records = json.loads(captured)
    (output_dir / 'fixture.json').write_text(captured, encoding='utf-8')
    header = render_header(model(records), module_name='fixture')
    path = output_dir / 'fixture.h'
    path.write_text(header, encoding='utf-8')
    point_type = check_retained_declarations(header)
    consumer = output_dir / 'use_fixture.m'
    consumer.write_text('''#include "fixture.h"
_Static_assert(sizeof(FIXTURE_POINT_TYPE) == 2 * sizeof(double), "record size");
_Static_assert(_Alignof(FIXTURE_POINT_TYPE) == _Alignof(double), "record alignment");
void exercise(EXChild *value) {
    int numbers[3] = {0};
    [value fillNumbers:&numbers];
    FIXTURE_POINT_TYPE point = [value translatePoint:(FIXTURE_POINT_TYPE){0}];
    long long count = [value count];
    Class cls = [EXChild relatedClass];
    SEL operation = [value operation];
    id<EXReadable> reader = value.delegate;
    NSString *name = value.name;
    double fraction = value.fraction;
    NSUInteger capacity = EXChild.capacity;
    (void)point; (void)count; (void)cls; (void)operation;
    (void)reader; (void)name; (void)fraction; (void)capacity;
}
'''.replace('FIXTURE_POINT_TYPE', point_type), encoding='utf-8')
    sdk = subprocess.check_output(['xcrun', '--show-sdk-path'], text=True).strip()
    targets = ['arm64-apple-macos11', 'x86_64-apple-macos11']
    for target in targets:
        subprocess.run(['xcrun', 'clang', '-fsyntax-only', '-fobjc-arc', '-Werror',
                        '-x', 'objective-c', '-target', target, '-isysroot', sdk,
                        str(consumer)], check=True)
    report = dict(runtime_architecture=platform.machine(),
                  classes=len(records['classes']), protocols=len(records['protocols']),
                  categories=len(records['categories']), compiled_targets=targets,
                  header=str(path), source=str(fixture))
    (output_dir / 'validation.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path,
                        help='retain executable, runtime records, header and validation report here')
    args = parser.parse_args()
    if args.output_dir:
        validate(args.output_dir.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix='objc-header-validation-') as directory:
            validate(Path(directory))


if __name__ == '__main__':
    main()
