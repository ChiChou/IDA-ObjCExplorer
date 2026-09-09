import io
import re
import unittest
from types import SimpleNamespace

from objc_explorer.headers import render_header, write_header
from objc_explorer.runtime import Method, Property, Ivar, ObjCClass, ObjCProtocol, ObjCCategory


def snapshot(classes=(), protocols=(), categories=(), **extra):
    return SimpleNamespace(classes=list(classes), protocols=list(protocols),
                           categories=list(categories), diagnostics=[], cancelled=False,
                           pointer_size=8, **extra)


def method(name, encoding, **extra):
    return Method(name, encoding, 0, 0, **extra)


class HeaderTests(unittest.TestCase):
    def test_basic_methods_unicode_and_stream_api(self):
        cls = ObjCClass('Exämple', 1, superclass='NSObject', methods=[
            method('run:', 'v24@0:8@16'), method('count', 'q16@0:8', is_class=True)])
        data = snapshot([cls])
        output = io.StringIO()
        write_header(data, output, 'test-module')
        text = output.getvalue()
        self.assertEqual(text, render_header(data, 'test-module'))
        self.assertIn('@interface Exämple : NSObject', text)
        self.assertIn('- (void)run:(id)arg0;', text)
        self.assertIn('+ (long long)count;', text)

    def test_const_pointer_and_nested_array_declarators(self):
        cls = ObjCClass('Example', 1, methods=[
            method('text:', 'v24@0:8r*16'), method('matrix:', 'v24@0:8^[3i]16')],
            ivars=[Ivar('values', '[2^i]', 1)])
        text = render_header(snapshot([cls]))
        self.assertIn('- (void)text:(const char *)arg0;', text)
        self.assertIn('- (void)matrix:(int (*)[3])arg0;', text)
        self.assertIn('int *values[2];', text)

    def test_method_direction_qualifier(self):
        cls = ObjCClass('Example', 1, methods=[method('fetch:', 'v24@0:8o^@16')])
        self.assertIn('- (void)fetch:(out id *)arg0;', render_header(snapshot([cls])))

    def test_objects_protocols_and_custom_property_accessors(self):
        cls = ObjCClass('Example', 1, properties=[
            Property('name', 'T@"NSString<NSCopying>",C,N,GdisplayName,SupdateDisplayName:,V_name', 1)],
            methods=[method('displayName', '@16@0:8'), method('updateDisplayName:', 'v24@0:8@16')])
        text = render_header(snapshot([cls]))
        self.assertIn('@property (nonatomic, copy, getter=displayName, setter=updateDisplayName:) NSString<NSCopying> *name;', text)
        self.assertIn('Accessor -updateDisplayName: is declared by its property', text)
        self.assertNotIn('\n- (void)updateDisplayName:', text)

    def test_optional_and_class_protocol_members(self):
        proto = ObjCProtocol('ExampleProtocol', 1, methods=[
            method('required', 'v16@0:8'),
            method('optional', '#16@0:8', optional=True, is_class=True)])
        text = render_header(snapshot(protocols=[proto]))
        self.assertIn('@optional\n+ (Class)optional;', text)
        self.assertIn('- (void)required;', text)

    def test_class_and_protocol_dependency_order_and_category(self):
        base = ObjCClass('ZBase', 1, superclass='NSObject')
        child = ObjCClass('AChild', 2, superclass='ZBase')
        parent = ObjCProtocol('ZProtocol', 3)
        sub = ObjCProtocol('AProtocol', 4, protocols=['ZProtocol'])
        category = ObjCCategory('Extras', 5, class_name='AChild', methods=[method('extra', ':16@0:8')])
        text = render_header(snapshot([child, base], [sub, parent], [category]))
        self.assertLess(text.index('@interface ZBase'), text.index('@interface AChild'))
        self.assertLess(text.index('@protocol ZProtocol\n'), text.index('@protocol AProtocol <'))
        self.assertLess(text.index('@interface AChild :'), text.index('@interface AChild (Extras)'))
        self.assertIn('- (SEL)extra;', text)

    def test_named_and_unnamed_record_fields_share_definition(self):
        cls = ObjCClass('Example', 1, methods=[method('point', '{Point=dd}16@0:8')],
                        ivars=[Ivar('_point', '{Point="x"d"y"d}', 1)])
        text = render_header(snapshot([cls]))
        self.assertEqual(len(re.findall(r'struct ObjCExplorer_Point_\w+ \{', text)), 1)
        self.assertIn('double x;', text)
        self.assertIn('double y;', text)
        self.assertNotIn('Omitted method -point', text)

    def test_union_and_pointer_array_record_dependency(self):
        cls = ObjCClass('Example', 1, ivars=[
            Ivar('record', '{A="items"^[2{Z=ii}]}', 1), Ivar('choice', '(Choice=if)', 2)])
        text = render_header(snapshot([cls]))
        z = re.search(r'struct ObjCExplorer_Z_\w+ \{', text)
        a = re.search(r'struct ObjCExplorer_A_\w+ \{', text)
        self.assertIsNotNone(z)
        self.assertIsNotNone(a)
        self.assertLess(z.start(), a.start())
        self.assertRegex(text, r'struct ObjCExplorer_Z_\w+ \(\*items\)\[2\];')
        self.assertRegex(text, r'union ObjCExplorer_Choice_\w+ \{')

    def test_incomplete_record_pointer_is_opaque_by_value_is_omitted(self):
        cls = ObjCClass('Example', 1, methods=[
            method('opaque:', 'v24@0:8^{Opaque}16'),
            method('value:', 'v24@0:8{Opaque}16')])
        text = render_header(snapshot([cls]))
        self.assertRegex(text, r'- \(void\)opaque:\(struct ObjCExplorer_Opaque_\w+ \*\)arg0;')
        self.assertIn('Omitted method -value:', text)

    def test_blocks_unknown_types_and_bad_selectors_remain_comments(self):
        cls = ObjCClass('Example', 1, methods=[method('block:', 'v24@0:8@?16'),
            method('function:', 'v24@0:8^?16'), method('wrong:', 'v16@0:8'),
            method('bad\n#error INJECT', 'v16@0:8'), method('good', 'v16@0:8')])
        text = render_header(snapshot([cls]))
        for name in ('block:', 'function:', 'wrong:'):
            self.assertIn('Omitted method -' + name, text)
        self.assertNotIn('\n#error', text)
        self.assertIn('- (void)good;', text)
        self.assertIn('encoding=v24@0:8@?16', text)

    def test_invalid_record_qualifier_does_not_abort_other_declarations(self):
        cls = ObjCClass('Example', 1, methods=[
            method('bad:', 'v24@0:8{Bad=ni}16'), method('good', 'v16@0:8')])
        text = render_header(snapshot([cls]))
        self.assertIn('Omitted method -bad:', text)
        self.assertIn('- (void)good;', text)
        self.assertNotRegex(text, r'struct ObjCExplorer_Bad_\w+ \{')

    def test_huge_array_numeric_input_and_deep_type_are_bounded(self):
        cls = ObjCClass('Example', 1, ivars=[Ivar('huge', '[' + '9' * 5000 + 'i]', 1),
                                          Ivar('deep', '^' * 100 + 'i', 2)])
        text = render_header(snapshot([cls]))
        self.assertIn('Omitted ivar huge', text)
        self.assertIn('Omitted ivar deep', text)
        self.assertIn('@end', text)

    def test_foundation_promoted_property_and_protocol_not_redeclared(self):
        cls = ObjCClass('Example', 1, superclass='NSObject',
                        properties=[Property('hash', 'TQ,R', 1)])
        text = render_header(snapshot([cls], [ObjCProtocol('NSObject', 2)]))
        self.assertIn('Property hash is already declared by NSObject/Foundation', text)
        self.assertNotIn('@protocol NSObject\n', text)
        self.assertNotIn('unsigned long long hash;', text)

    def test_cyclic_superclasses_are_diagnosed(self):
        text = render_header(snapshot([ObjCClass('A', 1, superclass='B'),
                                       ObjCClass('B', 2, superclass='A')]))
        self.assertIn('Omitted cyclic declaration A', text)
        self.assertNotIn('@interface A', text)

    def test_partial_results_diagnostics_and_comment_escaping(self):
        data = snapshot()
        data.cancelled = True
        data.diagnostics = ['bad */\n#error X\\']
        text = render_header(data, 'bad\n#endif')
        self.assertIn('Partial metadata', text)
        self.assertNotIn('\n#error', text)
        self.assertNotIn('bad */', text)
        self.assertTrue(text.endswith('_H\n'))


if __name__ == '__main__':
    unittest.main()
