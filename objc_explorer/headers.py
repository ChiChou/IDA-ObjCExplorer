"""Conservative Objective-C inspection headers from runtime type encodings.

The output is a declaration aid, not recovered source or an ABI layout promise.
Unknown signatures remain comments. Foundation supplies common external types;
other external superclass definitions must be supplied by the consumer.

Encoding reference: clang/lib/AST/ASTContext.cpp, getObjCEncodingForTypeImpl.
"""

from dataclasses import dataclass, replace
import hashlib
import json
import re


class EncodingError(ValueError):
    pass


_KEYWORDS = set(('auto break case char const continue default do double else enum '
                 'extern float for goto if inline int long register restrict return '
                 'short signed sizeof static struct switch typedef union unsigned '
                 'void volatile while _Bool _Complex _Imaginary id Class SEL self '
                 'super nil Nil YES NO true false bool').split())
_QUALIFIERS = {'r': 'const', 'n': 'in', 'N': 'inout', 'o': 'out',
               'O': 'bycopy', 'R': 'byref', 'V': 'oneway'}
_PRIMITIVES = {'c': 'char', 'i': 'int', 's': 'short', 'l': 'int',
               'q': 'long long', 'C': 'unsigned char', 'I': 'unsigned int',
               'S': 'unsigned short', 'L': 'unsigned int', 'Q': 'unsigned long long',
               'f': 'float', 'd': 'double', 'D': 'long double', 'B': 'bool',
               'v': 'void', '#': 'Class', ':': 'SEL'}
_FOUNDATION_PROTOCOLS = {'NSObject', 'NSCopying', 'NSMutableCopying', 'NSCoding',
                         'NSSecureCoding', 'NSFastEnumeration', 'NSDiscardableContent',
                         'NSXPCListenerDelegate', 'NSProgressReporting', 'NSLocking'}


def _identifier(value):
    return isinstance(value, str) and value.isidentifier() and value not in _KEYWORDS


def _safe(value):
    """A single comment line, including protection from line splicing."""
    return json.dumps(str(value), ensure_ascii=True)[1:-1].replace('*/', '* /') + ' '


def _comment(message):
    return '// ' + _safe(message)


@dataclass(frozen=True)
class _Type:
    kind: str
    name: str = ''
    child: object = None
    count: int = 0
    fields: object = None
    qualifiers: tuple = ()
    protocols: tuple = ()


class _Parser:
    def __init__(self, text):
        if not isinstance(text, str) or len(text) > 65536:
            raise EncodingError('missing or excessive type encoding')
        self.text, self.at, self.nodes = text, 0, 0

    def quoted(self):
        self.at += 1
        end = self.text.find('"', self.at)
        if end < 0:
            raise EncodingError('unterminated quoted name')
        value = self.text[self.at:end]
        self.at = end + 1
        return value

    def type(self, depth=0):
        self.nodes += 1
        if depth > 48 or self.nodes > 4096:
            raise EncodingError('type nesting or node limit exceeded')
        qualifiers = []
        while self.at < len(self.text) and self.text[self.at] in _QUALIFIERS:
            qualifiers.append(self.text[self.at])
            self.at += 1
        if self.at >= len(self.text):
            raise EncodingError('truncated type encoding')
        code = self.text[self.at]
        self.at += 1
        if code in _PRIMITIVES:
            value = _Type('primitive', code)
        elif code == '*':
            value = _Type('pointer', child=_Type('primitive', 'c'))
        elif code == '^':
            value = _Type('pointer', child=self.type(depth + 1))
        elif code == '@':
            if self.text[self.at:self.at + 1] == '?':
                raise EncodingError('block encoding does not specify its signature')
            name, protocols = '', ()
            if self.text[self.at:self.at + 1] == '"':
                encoded = self.quoted()
                match = re.fullmatch(r'([^<>]*)(<[^<>]+>)*', encoded)
                if not match:
                    raise EncodingError('invalid object qualification')
                name = encoded.split('<', 1)[0]
                protocols = tuple(re.findall(r'<([^<>]+)>', encoded))
                if (name and not _identifier(name)) or any(not _identifier(p) for p in protocols):
                    raise EncodingError('invalid object or protocol identifier')
            value = _Type('object', name, protocols=protocols)
        elif code == '[':
            first = self.at
            while self.at < len(self.text) and self.text[self.at] in '0123456789':
                self.at += 1
            if self.at == first:
                raise EncodingError('array length is missing')
            if self.at - first > 7:
                raise EncodingError('excessive array length')
            count = int(self.text[first:self.at])
            if count < 1 or count > 1000000:
                raise EncodingError('unknown or excessive array length')
            child = self.type(depth + 1)
            if self.text[self.at:self.at + 1] != ']':
                raise EncodingError('unterminated array')
            self.at += 1
            value = _Type('array', child=child, count=count)
        elif code in '{(':
            end = '}' if code == '{' else ')'
            first = self.at
            while self.at < len(self.text) and self.text[self.at] not in '=' + end:
                self.at += 1
            name = self.text[first:self.at]
            if not name or (name != '?' and not _identifier(name)):
                raise EncodingError('invalid aggregate name')
            fields = None
            if self.text[self.at:self.at + 1] == '=':
                self.at += 1
                fields = []
                while self.at < len(self.text) and self.text[self.at] != end:
                    field_name = self.quoted() if self.text[self.at] == '"' else ''
                    fields.append((field_name, self.type(depth + 1)))
                fields = tuple(fields)
            if self.text[self.at:self.at + 1] != end:
                raise EncodingError('unterminated aggregate')
            self.at += 1
            value = _Type('struct' if code == '{' else 'union', name, fields=fields)
        else:
            raise EncodingError('unsupported type token %r' % code)
        return replace(value, qualifiers=tuple(qualifiers))

    def offset(self):
        signed = False
        if self.text[self.at:self.at + 1] in ('+', '-'):
            self.at += 1
            signed = True
        first = self.at
        while self.at < len(self.text) and self.text[self.at] in '0123456789':
            self.at += 1
        if signed and first == self.at:
            raise EncodingError('malformed encoded offset')

    def single(self):
        result = self.type()
        if self.at != len(self.text):
            raise EncodingError('trailing type encoding')
        return result

    def method(self):
        result = []
        while self.at < len(self.text):
            result.append(self.type())
            self.offset()
        if len(result) < 3 or result[1].kind != 'object' or result[2].name != ':':
            raise EncodingError('missing or invalid hidden self/_cmd arguments')
        return result[0], result[3:]


def _shape(t):
    if t.kind in ('struct', 'union') and t.name != '?':
        return t.kind, t.name
    return (t.kind, t.name, t.count, t.qualifiers, t.protocols,
            _shape(t.child) if t.child else None,
            tuple(_shape(field) for _, field in t.fields) if t.fields else None)


class _Header:
    def __init__(self, data, module_name):
        self.data = data
        self.module_name = module_name
        self.records, self.conflicts, self.classes, self.protocols = {}, set(), set(), set()
        self.cache = {}
        self.pointer_size = getattr(data, 'pointer_size', 8)

    def record_key(self, t):
        return (t.kind, t.name) if t.name != '?' else (t.kind, repr(_shape(t)))

    def tag(self, t):
        key = self.record_key(t)
        digest = hashlib.sha256(repr(key).encode()).hexdigest()[:12]
        readable = t.name if t.name != '?' else 'Anonymous'
        return 'ObjCExplorer_%s_%s' % (readable, digest)

    def collect(self, t):
        if t.kind == 'object':
            if t.name:
                self.classes.add(t.name)
            self.protocols.update(t.protocols)
        if t.child:
            self.collect(t.child)
        if t.kind in ('struct', 'union'):
            key = self.record_key(t)
            existing = self.records.get(key)
            if existing and existing.fields and t.fields:
                if tuple(_shape(x) for _, x in existing.fields) != tuple(_shape(x) for _, x in t.fields):
                    self.conflicts.add(key)
                elif sum(bool(n) for n, _ in t.fields) > sum(bool(n) for n, _ in existing.fields):
                    self.records[key] = t
            elif not existing or t.fields:
                self.records[key] = t
            for _, field in t.fields or ():
                self.collect(field)

    def parse(self, encoding, method=False):
        key = encoding, method
        if key not in self.cache:
            try:
                parser = _Parser(encoding)
                value = parser.method() if method else parser.single()
                for t in [value[0]] + value[1] if method else [value]:
                    self.collect(t)
                self.cache[key] = value
            except EncodingError as exc:
                self.cache[key] = exc
        value = self.cache[key]
        if isinstance(value, EncodingError):
            raise value
        return value

    def complete(self, t, seen=()):
        def supported_qualifiers(field):
            return (all(q == 'r' for q in field.qualifiers)
                    and (not field.child or supported_qualifiers(field.child))
                    and all(supported_qualifiers(child) for _, child in field.fields or ()))
        if not supported_qualifiers(t):
            return False
        if t.kind == 'pointer':
            return t.child.kind != 'array' or self.complete(t.child, seen)
        if t.kind == 'array':
            return self.complete(t.child, seen) and t.child.name != 'v'
        if t.kind not in ('struct', 'union'):
            return True
        key = self.record_key(t)
        record = self.records.get(key)
        return (key not in seen and key not in self.conflicts and record is not None
                and bool(record.fields)
                and all(field.name != 'v' and self.complete(field, seen + (key,))
                        for _, field in record.fields))

    def declaration(self, t, name='', indirect=False, readonly=False):
        if any(q != 'r' for q in t.qualifiers):
            raise EncodingError('method-only qualifier outside a method type')
        readonly = readonly or 'r' in t.qualifiers
        if t.kind == 'pointer':
            decorated = '*' + name
            if t.child.kind == 'array':
                decorated = '(' + decorated + ')'
            return self.declaration(t.child, decorated, True, readonly)
        if t.kind == 'array':
            if not self.complete(t):
                raise EncodingError('array has an incomplete element type')
            return self.declaration(t.child, '%s[%d]' % (name, t.count), False, readonly)
        if t.kind == 'primitive':
            base = _PRIMITIVES[t.name]
            if self.pointer_size == 4 and t.name in ('l', 'L'):
                base = 'long' if t.name == 'l' else 'unsigned long'
        elif t.kind == 'object':
            suffix = '<' + ', '.join(t.protocols) + '>' if t.protocols else ''
            base = (t.name or 'id') + suffix
            if t.name:
                name = '*' + name
        else:
            if not indirect and not self.complete(t):
                raise EncodingError('aggregate layout is incomplete or conflicting')
            base = t.kind + ' ' + self.tag(t)
        return (('const ' if readonly else '') + base + (' ' + name if name else '')).strip()

    def method_type(self, t, is_return=False):
        if t.kind == 'array' or (not is_return and t.name == 'v'):
            raise EncodingError('invalid method return or argument type')
        qualifiers = [_QUALIFIERS[q] for q in t.qualifiers if q != 'r']
        if 'oneway' in qualifiers and (not is_return or t.name != 'v'):
            raise EncodingError('oneway requires a void return')
        plain = replace(t, qualifiers=tuple(q for q in t.qualifiers if q == 'r'))
        return ' '.join(qualifiers + [self.declaration(plain)])

    def property_info(self, prop):
        if not _identifier(prop.name) or not prop.attributes.startswith('T'):
            raise EncodingError('invalid property name or missing type')
        parser = _Parser(prop.attributes[1:])
        parser.type()
        type_text = parser.text[:parser.at]
        suffix = parser.text[parser.at:]
        if suffix and not suffix.startswith(','):
            raise EncodingError('invalid property attributes')
        t = self.parse(type_text)
        if t.kind == 'array' or t.name == 'v':
            raise EncodingError('unsupported property type')
        flags, attributes = {}, []
        for item in suffix.lstrip(',').split(',') if suffix else []:
            if not item or item[0] in flags:
                raise EncodingError('duplicate or empty property attribute')
            flags[item[0]] = item[1:]
        if set(flags) - set('RC&NWGSDVP'):
            raise EncodingError('unsupported property attribute')
        if any(value for key, value in flags.items() if key not in 'GSV'):
            raise EncodingError('invalid property attribute payload')
        ownership = [key for key in ('C', '&', 'W') if key in flags]
        if len(ownership) > 1 or (ownership and t.kind != 'object'):
            raise EncodingError('invalid property ownership attributes')
        if prop.is_class:
            attributes.append('class')
        attributes.append('nonatomic' if 'N' in flags else 'atomic')
        if 'R' in flags:
            attributes.append('readonly')
        if ownership:
            attributes.append({'C': 'copy', '&': 'strong', 'W': 'weak'}[ownership[0]])
        elif 'R' not in flags:
            attributes.append('assign')
        getter = flags.get('G', prop.name)
        setter = flags.get('S', 'set' + prop.name[:1].upper() + prop.name[1:] + ':')
        if not _identifier(getter) or not setter.endswith(':') or not _identifier(setter[:-1]):
            raise EncodingError('invalid property accessor selector')
        if 'G' in flags:
            attributes.append('getter=' + getter)
        if 'S' in flags:
            attributes.append('setter=' + setter)
        declaration = '@property (%s) %s;' % (', '.join(attributes), self.declaration(t, prop.name))
        return declaration, getter, None if 'R' in flags else setter, t

    def method(self, method):
        result, arguments = self.parse(method.types, True)
        if ':' in method.name:
            components = method.name.split(':')
            if components[-1] or any(not _identifier(c) for c in components[:-1]):
                raise EncodingError('invalid selector')
            components = components[:-1]
        else:
            if not _identifier(method.name):
                raise EncodingError('invalid selector')
            components = []
        if len(components) != len(arguments):
            raise EncodingError('selector and argument counts differ')
        prefix = ('+' if method.is_class else '-') + ' (' + self.method_type(result, True) + ')'
        if not components:
            return prefix + method.name + ';'
        return prefix + ' '.join('%s:(%s)arg%d' % (c, self.method_type(t), i)
                                 for i, (c, t) in enumerate(zip(components, arguments))) + ';'

    def members(self, obj, protocol=False):
        lines, accessors = [], {}
        optional = False
        for prop in sorted(obj.properties, key=lambda p: (p.is_class, p.name, p.attributes)):
            try:
                declaration, getter, setter, t = self.property_info(prop)
                accessors[(prop.is_class, getter)] = (False, t)
                if setter:
                    accessors[(prop.is_class, setter)] = (True, t)
                if self.foundation_property(obj, prop, t):
                    lines.append(_comment('Property %s is already declared by NSObject/Foundation' % prop.name))
                    continue
                getter_methods = [m for m in obj.methods if m.name == getter and m.is_class == prop.is_class]
                property_optional = bool(getter_methods and all(m.optional for m in getter_methods))
                if protocol and optional != property_optional:
                    optional = property_optional
                    lines.append('@optional' if optional else '@required')
                lines.append(declaration)
            except EncodingError as exc:
                lines.append(_comment('Omitted property %s: %s; attributes=%s' % (prop.name, exc, prop.attributes)))
        seen = set()
        for method in sorted(obj.methods, key=lambda m: (m.optional, m.is_class, m.name, m.types)):
            key = method.is_class, method.name
            try:
                declaration = self.method(method)
                if key in accessors:
                    lines.append(_comment('Accessor %s%s is declared by its property; encoding=%s' %
                                          ('+' if method.is_class else '-', method.name, method.types)))
                    continue
                if key in seen:
                    raise EncodingError('duplicate selector declaration')
                seen.add(key)
                if protocol and optional != method.optional:
                    optional = method.optional
                    lines.append('@optional' if optional else '@required')
                lines.append(declaration)
            except EncodingError as exc:
                lines.append(_comment('Omitted method %s%s: %s; encoding=%s' %
                                      ('+' if method.is_class else '-', method.name, exc, method.types)))
        return lines

    def foundation_property(self, obj, prop, t):
        """Avoid redeclaring promoted NSObject properties with erased typedefs."""
        if prop.is_class or 'R' not in prop.attributes.split(',')[1:]:
            return False
        known = {c.name: c for c in self.data.classes}
        parent, visited = getattr(obj, 'superclass', ''), set()
        while parent and parent not in visited and parent != 'NSObject':
            visited.add(parent)
            parent = getattr(known.get(parent), 'superclass', '')
        if parent != 'NSObject':
            return False
        return ((prop.name == 'hash' and t.kind == 'primitive' and t.name in ('I', 'L', 'Q'))
                or (prop.name == 'superclass' and t.kind == 'primitive' and t.name == '#')
                or (prop.name in ('description', 'debugDescription') and t.kind == 'object'
                    and t.name == 'NSString'))

    def adoption(self, obj):
        names = sorted(set(p for p in obj.protocols if _identifier(p)))
        return ' <' + ', '.join(names) + '>' if names else ''

    def ordered(self, objects, dependency):
        pending = sorted(objects, key=lambda obj: (obj.name, obj.ea))
        while pending:
            names = {obj.name for obj in pending}
            ready = [obj for obj in pending if not (set(dependency(obj)) & names)]
            if not ready:
                break
            yield from ready
            pending = [obj for obj in pending if obj not in ready]
        for obj in pending:
            yield _comment('Omitted cyclic declaration %s at 0x%X' % (obj.name, obj.ea))

    def render(self):
        objects = list(self.data.classes) + list(self.data.protocols) + list(self.data.categories)
        for obj in objects:
            self.protocols.update(p for p in obj.protocols if _identifier(p))
            for method in obj.methods:
                try:
                    self.parse(method.types, True)
                except EncodingError:
                    pass
            for prop in obj.properties:
                try:
                    self.property_info(prop)
                except EncodingError:
                    pass
            for ivar in getattr(obj, 'ivars', []):
                try:
                    self.parse(ivar.types)
                except EncodingError:
                    pass
        classes = [obj for obj in self.data.classes if _identifier(obj.name)]
        protocols = [obj for obj in self.data.protocols if _identifier(obj.name)]
        self.classes.update(obj.name for obj in classes)
        self.protocols.update(obj.name for obj in protocols)
        self.classes.update(obj.superclass for obj in classes if _identifier(obj.superclass))
        self.classes.update(obj.class_name for obj in self.data.categories if _identifier(obj.class_name))
        guard = 'OBJCEXPLORER_' + re.sub('[^A-Za-z0-9_]', '_', str(self.module_name)).upper() + '_H'
        lines = [_comment('Objective-C inspection header: ' + str(self.module_name)),
                 '// Generated argument/aggregate names are synthetic. Source typedefs, nullability,',
                 '// variadics, ownership details and packed/aligned layouts may not be recoverable.',
                 '// Omitted declarations retain their raw encodings in comments.',
                 '#ifndef ' + guard, '#define ' + guard, '',
                 '#import <Foundation/Foundation.h>', '#include <stdbool.h>', '']
        if getattr(self.data, 'cancelled', False):
            lines.append('// Partial metadata: parsing was cancelled.')
        for obj in objects:
            if not _identifier(obj.name):
                lines.append(_comment('Omitted invalid declaration name: ' + obj.name))
        if self.classes:
            lines.append('@class ' + ', '.join(sorted(self.classes)) + ';')
        if self.protocols:
            lines.append('@protocol ' + ', '.join(sorted(self.protocols)) + ';')
        lines.append('')
        for _, t in sorted(self.records.items()):
            lines.append('%s %s;' % (t.kind, self.tag(t)))
        remaining = [t for _, t in sorted(self.records.items()) if self.complete(t)]
        emitted = set()
        while remaining:
            progressed = False
            for t in list(remaining):
                def dependencies(child):
                    if child.kind == 'pointer':
                        return dependencies(child.child) if child.child.kind == 'array' else set()
                    if child.kind == 'array':
                        return dependencies(child.child)
                    return {self.record_key(child)} if child.kind in ('struct', 'union') else set()
                needed = set().union(*(dependencies(child) for _, child in t.fields))
                if not needed <= emitted:
                    continue
                lines.append(_comment('Encoded aggregate ' + t.name + '; field names may be synthetic'))
                lines.append('%s %s {' % (t.kind, self.tag(t)))
                used = set()
                for i, (name, field) in enumerate(t.fields):
                    name = name if _identifier(name) and name not in used else 'field%d' % i
                    while name in used:
                        name += '_'
                    used.add(name)
                    lines.append('    ' + self.declaration(field, name) + ';')
                lines.append('};\n')
                emitted.add(self.record_key(t))
                remaining.remove(t)
                progressed = True
            if not progressed:
                break
        for obj in self.ordered([p for p in protocols if p.name not in _FOUNDATION_PROTOCOLS], lambda p: p.protocols):
            if isinstance(obj, str):
                lines.append(obj)
                continue
            lines += ['@protocol ' + obj.name + self.adoption(obj)] + self.members(obj, True) + ['@end\n']
        for obj in protocols:
            if obj.name in _FOUNDATION_PROTOCOLS:
                lines.append(_comment('Protocol %s supplied by Foundation; runtime redeclaration omitted' % obj.name))
        for obj in self.ordered(classes, lambda c: [c.superclass] if c.superclass else []):
            if isinstance(obj, str):
                lines.append(obj)
                continue
            if obj.superclass and not _identifier(obj.superclass):
                lines.append(_comment('Omitted class %s: invalid superclass %s' % (obj.name, obj.superclass)))
                continue
            if obj.superclass and obj.superclass not in {c.name for c in classes} and obj.superclass != 'NSObject':
                lines.append(_comment('Requires an external superclass definition: ' + obj.superclass))
            lines.append('@interface ' + obj.name + (' : ' + obj.superclass if obj.superclass else '') + self.adoption(obj))
            if obj.ivars:
                lines += ['{', '@private']
                for ivar in obj.ivars:
                    try:
                        if not _identifier(ivar.name):
                            raise EncodingError('invalid or absent ivar name')
                        t = self.parse(ivar.types)
                        if t.name == 'v':
                            raise EncodingError('void ivar')
                        lines.append('    ' + self.declaration(t, ivar.name) + ';')
                    except EncodingError as exc:
                        lines.append('    ' + _comment('Omitted ivar %s: %s; encoding=%s' % (ivar.name, exc, ivar.types)))
                lines.append('}')
            lines += self.members(obj) + ['@end\n']
        for obj in sorted(self.data.categories, key=lambda c: (c.class_name, c.name, c.ea)):
            if not _identifier(obj.class_name) or not _identifier(obj.name):
                lines.append(_comment('Omitted category %s(%s): invalid or unresolved name' % (obj.class_name, obj.name)))
                continue
            lines += ['@interface %s (%s)%s' % (obj.class_name, obj.name, self.adoption(obj))] + self.members(obj) + ['@end\n']
        for diagnostic in getattr(self.data, 'diagnostics', []):
            lines.append(_comment('Metadata: ' + diagnostic))
        lines += ['', '#endif // ' + guard, '']
        return '\n'.join(lines)


def render_header(data, module_name='module'):
    """Return a deterministic inspection header for an ObjCRuntime snapshot."""
    return _Header(data, module_name).render()


def write_header(data, output, module_name='module'):
    """Write an inspection header to a text file-like object."""
    output.write(render_header(data, module_name))
