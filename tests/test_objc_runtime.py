import struct
import unittest

from objc_explorer.runtime import DIRECT_SELECTORS, DIRECT_TYPES, SMALL_METHOD_LIST, ObjCRuntime


class Image:
    """Sparse image fixture: no platform runtime or IDA dependency."""

    pointer_size = 8

    def __init__(self, pointer_size=8):
        self.pointer_size = pointer_size
        self.memory = {}
        self.next_ea = 0x1000
        self.section_list = []
        self.fixups = {}

    def allocate(self, data):
        ea = self.next_ea
        self.next_ea += (len(data) + 15) & ~15
        self.write(ea, data)
        return ea

    def write(self, ea, data):
        self.memory.update((ea + index, byte) for index, byte in enumerate(data))

    def read(self, ea, size):
        return bytes(self.memory[ea + index] for index in range(size))

    def mapped(self, ea, size):
        return all(ea + index in self.memory for index in range(size))

    def pointer(self, ea):
        if ea in self.fixups:
            return self.fixups[ea]
        return int.from_bytes(self.read(ea, self.pointer_size), "little")

    def string(self, ea):
        data = bytearray()
        while self.memory[ea]:
            data.append(self.memory[ea])
            ea += 1
        return data.decode("utf-8")

    def segments(self):
        return iter(self.section_list)

    def cstring(self, value):
        return self.allocate(value.encode("utf-8") + b"\0")

    def pointers(self, *values):
        return b"".join(value.to_bytes(self.pointer_size, "little") for value in values)

    def section(self, name, *values):
        ea = self.allocate(self.pointers(*values))
        self.section_list.append((name, ea, ea + len(values) * self.pointer_size))
        return ea

    def methods(self, methods, relative=False, direct=False, stride=None):
        p = self.pointer_size
        stride = stride or (12 if relative else 3 * p)
        refs = [(self.cstring(name), self.cstring(types), imp) for name, types, imp in methods]
        flags = stride | (SMALL_METHOD_LIST if relative else 0) | (DIRECT_SELECTORS if direct else 0)
        ea = self.allocate(struct.pack("<II", flags, len(refs)) + bytes(stride * len(refs)))
        for index, (name, types, imp) in enumerate(refs):
            entry = ea + 8 + index * stride
            if relative:
                if not direct:
                    name = self.allocate(self.pointers(name))
                imp_offset = imp - (entry + 8) if imp else 0
                self.write(entry, struct.pack("<iii", name - entry, types - (entry + 4), imp_offset))
            else:
                self.write(entry, self.pointers(name, types, imp))
        return ea

    def properties(self, name="value", attributes='T@"NSString",C,N,V_value'):
        return self.allocate(struct.pack("<II", 2 * self.pointer_size, 1) +
                             self.pointers(self.cstring(name), self.cstring(attributes)))

    def ro(self, name, methods=0, properties=0, protocols=0, ivars=0, flags=0):
        head = struct.pack("<III", flags, self.pointer_size, 32)
        if self.pointer_size == 8:
            head += bytes(4)
        return self.allocate(head + self.pointers(0, self.cstring(name), methods,
                                                 protocols, ivars, 0, properties))

    def cls(self, name="Example", methods=0, class_methods=0, data_flags=0,
            properties=0, protocols=0, ivars=0, superclass=0):
        meta_ro = self.ro(name, class_methods, flags=1)
        meta = self.allocate(self.pointers(0, 0, 0, 0, meta_ro | data_flags))
        ro = self.ro(name, methods, properties, protocols, ivars)
        return self.allocate(self.pointers(meta, superclass, 0, 0, ro | data_flags))

    def protocol(self, name="ExampleProtocol", lists=None, size=None, class_properties=0):
        p = self.pointer_size
        lists = lists or (0, 0, 0, 0)
        size = size if size is not None else 11 * p + 8
        data = self.pointers(0, self.cstring(name), 0, *lists, 0)
        data += struct.pack("<II", size, 0)
        if size > len(data):
            data += self.pointers(0, 0, class_properties)[:size - len(data)]
        return self.allocate(data)


class MethodTests(unittest.TestCase):
    def test_absolute_methods_follow_entry_stride_and_preserve_encoding(self):
        image = Image()
        ea = image.methods([("one:", "v24@0:8i16", 0x3000), ("two", "@16@0:8", 0x4000)], stride=32)
        # Low bits store fixup state, not the entry size.
        image.write(ea, struct.pack("<I", 32 | 3))
        methods = ObjCRuntime(image).methods(ea, is_class=True)
        self.assertEqual([method.key for method in methods], ["+ one:", "+ two"])
        self.assertEqual(methods[0].types, "v24@0:8i16")
        self.assertEqual(methods[1].imp, 0x4000)
        self.assertEqual(methods[1].ea - methods[0].ea, 32)

    def test_relative_indirect_selectors_and_negative_offsets(self):
        image = Image()
        ea = image.methods([("setValue:", "v24@0:8@16", 0x800)], relative=True)
        methods = ObjCRuntime(image).methods(ea)
        self.assertEqual(methods[0].name, "setValue:")
        self.assertEqual(methods[0].types, "v24@0:8@16")
        self.assertEqual(methods[0].imp, 0x800)

    def test_direct_relative_selectors_are_not_dereferenced(self):
        image = Image()
        ea = image.methods([("direct", "v16@0:8", 0x2000)], relative=True, direct=True)
        self.assertEqual(ObjCRuntime(image).methods(ea)[0].name, "direct")

    def test_shared_cache_selector_base_is_used_when_supplied(self):
        image = Image()
        ea = image.methods([("cacheSelector", "v16@0:8", 0x2000)], relative=True, direct=True)
        entry = ea + 8
        name_ea = entry + int.from_bytes(image.read(entry, 4), "little", signed=True)
        base = name_ea - 0x400
        image.write(entry, struct.pack("<I", name_ea - base))
        image.relative_selector_base = lambda address: base if address == ea else None
        self.assertEqual(ObjCRuntime(image).methods(ea)[0].name, "cacheSelector")

    def test_shared_cache_base_does_not_override_indirect_list(self):
        image = Image()
        ea = image.methods([("indirect", "v16@0:8", 0x2000)], relative=True)
        image.relative_selector_base = 0x100000000
        self.assertEqual(ObjCRuntime(image).methods(ea)[0].name, "indirect")

    def test_cache_selector_buffer_offsets_are_unsigned(self):
        image = Image()
        ea = image.methods([("unused", "v16@0:8", 0x2000)], relative=True, direct=True)
        image.relative_selector_base = 0x1000
        offset = 0x80001000
        image.write(image.relative_selector_base + offset, b"farSelector\0")
        image.write(ea + 8, struct.pack("<I", offset))
        self.assertEqual(ObjCRuntime(image).methods(ea)[0].name, "farSelector")

    def test_cache_type_offsets_use_selector_buffer_including_offset_zero(self):
        image = Image()
        base = image.cstring("v16@0:8")
        name_ea = image.cstring("typedSelector")
        flags = SMALL_METHOD_LIST | DIRECT_SELECTORS | DIRECT_TYPES | 12
        ea = image.allocate(struct.pack("<IIIII", flags, 1, name_ea - base, 0, 0))
        image.relative_selector_base = base
        method = ObjCRuntime(image).methods(ea)[0]
        self.assertEqual((method.name, method.types, method.imp), ("typedSelector", "v16@0:8", 0))
        self.assertEqual(method.types_ea, base)

    def test_cache_type_offsets_without_base_produce_diagnostic(self):
        image = Image()
        flags = SMALL_METHOD_LIST | DIRECT_SELECTORS | DIRECT_TYPES | 12
        ea = image.allocate(struct.pack("<IIIII", flags, 1, 16, 24, 0))
        runtime = ObjCRuntime(image)
        self.assertEqual(runtime.methods(ea), [])
        self.assertIn("selector/type base is unavailable", runtime.diagnostics[0])

    def test_null_relative_types_are_empty(self):
        image = Image()
        ea = image.methods([("withoutTypes", "ignored", 0x2000)], relative=True)
        image.write(ea + 12, bytes(4))
        self.assertEqual(ObjCRuntime(image).methods(ea)[0].types, "")

    def test_format_is_detected_from_header_not_segment_name(self):
        image = Image()
        ea = image.methods([("ordinary", "v16@0:8", 0x3000)])
        image.section_list.append(("libExample:__objc_methlist", ea, ea + 32))
        self.assertEqual(ObjCRuntime(image).methods(ea)[0].imp, 0x3000)

    def test_pointer_resolution_is_delegated_to_reader(self):
        image = Image()
        ea = image.methods([("resolved", "v16@0:8", 0x2000)])
        entry = ea + 8
        name_ea = image.pointer(entry)
        image.write(entry, image.pointers(0xDEADBEEF00000001))
        image.fixups[entry] = name_ea
        image.fixups[entry + 16] = 0x5000
        method = ObjCRuntime(image).methods(ea)[0]
        self.assertEqual((method.name, method.imp), ("resolved", 0x5000))

    def test_bad_entry_does_not_hide_following_method(self):
        image = Image()
        ea = image.methods([("bad", "v16@0:8", 0x2000), ("good", "v16@0:8", 0x3000)])
        image.write(ea + 8, image.pointers(0xDEADBEEF))
        runtime = ObjCRuntime(image)
        self.assertEqual([m.name for m in runtime.methods(ea)], ["good"])
        self.assertIn("unresolved string", runtime.diagnostics[0])

    def test_invalid_stride_and_huge_count_are_bounded(self):
        image = Image()
        invalid = image.allocate(struct.pack("<II", SMALL_METHOD_LIST | 8, 0xFFFFFFFF))
        runtime = ObjCRuntime(image)
        self.assertEqual(runtime.methods(invalid), [])
        self.assertIn("invalid entry size", runtime.diagnostics[0])
        ea = image.methods([("only", "v16@0:8", 0x2000)])
        image.write(ea + 4, struct.pack("<I", 0xFFFFFFFF))
        self.assertEqual(len(runtime.methods(ea)), 1)
        self.assertTrue(any("truncated list" in warning for warning in runtime.diagnostics))

    def test_relative_list_of_lists_handles_signed_48_bit_offset(self):
        image = Image()
        first = image.methods([("categoryMethod", "v16@0:8", 0x2000)])
        second = image.methods([("classMethod", "v16@0:8", 0x3000)])
        lists = image.allocate(struct.pack("<II", 8, 2) + bytes(16))
        for index, target in enumerate((first, second)):
            entry = lists + 8 + index * 8
            packed = (((target - entry) & ((1 << 48) - 1)) << 16) | index
            image.write(entry, struct.pack("<Q", packed))
        runtime = ObjCRuntime(image)
        self.assertEqual([m.name for m in runtime.methods(lists | 1)],
                         ["categoryMethod", "classMethod"])
        self.assertEqual(runtime.diagnostics, [])


class MetadataTests(unittest.TestCase):
    def test_prefixed_sections_deduplicate_classes_and_expose_swift_flags(self):
        image = Image()
        instance = image.methods([("instance", "v16@0:8", 0x2000)], relative=True)
        metaclass = image.methods([("factory", "@16@0:8", 0x3000)])
        superclass = image.cls(name="Base")
        ea = image.cls(methods=instance, class_methods=metaclass, data_flags=7, superclass=superclass)
        section = image.section("some:image:__objc_classlist", ea, ea)
        image.section("__objc_nlclslist", ea)
        runtime = ObjCRuntime(image).parse()
        self.assertEqual(len(runtime.classes), 1)
        obj = runtime.classes[0]
        self.assertEqual([method.key for method in obj.methods], ["+ factory", "- instance"])
        self.assertTrue(obj.is_swift)
        self.assertEqual(obj.superclass, "Base")
        self.assertIs(runtime.lookup[section], runtime.lookup[ea])
        self.assertEqual(runtime.diagnostics, [])

    def test_missing_metaclass_preserves_instance_methods(self):
        image = Image()
        methods = image.methods([("instance", "v16@0:8", 0x2000)])
        ea = image.cls(methods=methods)
        image.write(ea, image.pointers(0xBAD000))
        image.section("__objc_classlist", ea)
        runtime = ObjCRuntime(image).parse()
        self.assertEqual([m.name for m in runtime.classes[0].methods], ["instance"])
        self.assertIn("metaclass", runtime.diagnostics[0])

    def test_external_class_names_are_resolved_by_reader(self):
        image = Image()
        external = 0xF00000
        image.class_name = lambda ea: "NSObject" if ea == external else ""
        cls = image.cls(superclass=external)
        category = image.allocate(image.pointers(image.cstring("Extensions"), external, 0, 0, 0, 0))
        image.section("__objc_classlist", cls)
        image.section("__objc_catlist", category)
        runtime = ObjCRuntime(image).parse()
        self.assertEqual(runtime.classes[0].superclass, "NSObject")
        self.assertEqual(runtime.categories[0].class_name, "NSObject")
        self.assertEqual(runtime.diagnostics, [])

    def test_all_protocol_method_kinds_and_absent_implementation(self):
        image = Image()
        lists = [image.methods([(name, "v16@0:8", 0)]) for name in
                 ("requiredInstance", "requiredClass", "optionalInstance", "optionalClass")]
        ea = image.protocol(lists=lists, class_properties=image.properties())
        image.section("__objc_protolist", ea)
        runtime = ObjCRuntime(image).parse()
        protocol = runtime.protocols[0]
        self.assertEqual([(m.is_class, m.optional) for m in protocol.methods],
                         [(False, False), (True, False), (False, True), (True, True)])
        self.assertTrue(all(m.imp == 0 for m in protocol.methods))
        self.assertTrue(protocol.properties[0].is_class)
        self.assertEqual(runtime.diagnostics, [])

    def test_relative_protocol_methods_have_no_implementation(self):
        image = Image()
        methods = image.methods([("requiredMethod", "v16@0:8", 0)], relative=True)
        ea = image.protocol(lists=(methods, 0, 0, 0))
        image.section("__objc_protolist", ea)
        runtime = ObjCRuntime(image).parse()
        method = runtime.protocols[0].methods[0]
        self.assertEqual((method.name, method.imp), ("requiredMethod", 0))
        self.assertEqual(runtime.diagnostics, [])

    def test_old_protocol_size_does_not_read_optional_tail(self):
        image = Image()
        ea = image.protocol(size=72)
        image.section("__objc_protolist", ea)
        runtime = ObjCRuntime(image).parse()
        self.assertEqual(runtime.protocols[0].properties, [])
        self.assertEqual(runtime.diagnostics, [])

    def test_class_properties_ivars_and_protocol_conformance(self):
        image = Image()
        protocol = image.protocol()
        protocol_list = image.allocate(image.pointers(1, protocol))
        offset = image.allocate(struct.pack("<i", 16))
        ivars = image.allocate(struct.pack("<II", 32, 1) +
                               image.pointers(offset, image.cstring("_value"), image.cstring('@"NSString"')) +
                               struct.pack("<II", 3, 8))
        cls = image.cls(properties=image.properties(), protocols=protocol_list, ivars=ivars)
        image.section("__objc_classlist", cls)
        runtime = ObjCRuntime(image).parse()
        obj = runtime.classes[0]
        self.assertEqual(obj.protocols, ["ExampleProtocol"])
        self.assertEqual(obj.properties[0].attributes, 'T@"NSString",C,N,V_value')
        self.assertEqual((obj.ivars[0].offset, obj.ivars[0].alignment, obj.ivars[0].size), (16, 8, 8))
        self.assertEqual(runtime.diagnostics, [])

    def test_uninitialized_ivar_offset_preserves_declaration(self):
        image = Image()
        offset_storage = 0xF00000  # Runtime initialized storage with no file bytes.
        name = image.cstring("_$observationRegistrar")
        types = image.cstring("")
        ivars = image.allocate(struct.pack("<II", 32, 1) +
                               image.pointers(offset_storage, name, types) +
                               struct.pack("<II", 0, 0))
        cls = image.cls(ivars=ivars, data_flags=2)
        image.section("__objc_classlist", cls)
        runtime = ObjCRuntime(image).parse()
        self.assertEqual(len(runtime.classes[0].ivars), 1)
        ivar = runtime.classes[0].ivars[0]
        self.assertEqual((ivar.name, ivar.types, ivar.offset, ivar.size),
                         ("_$observationRegistrar", "", None, 0))
        self.assertIn("ivar offset at 0xF00000 unavailable", runtime.diagnostics[0])

    def test_category_instance_and_class_methods_and_version_gated_properties(self):
        image = Image()
        cls = image.cls()
        instance = image.methods([("added", "v16@0:8", 0x2000)])
        factory = image.methods([("make", "@16@0:8", 0x3000)])
        category = image.allocate(image.pointers(image.cstring("Extras"), cls,
                                                instance, factory, 0, image.properties()))
        image.section("__objc_catlist", category)
        image.section("__objc_nlcatlist", category)
        runtime = ObjCRuntime(image).parse()
        self.assertEqual(len(runtime.categories), 1)
        obj = runtime.categories[0]
        self.assertEqual((obj.class_name, obj.name), ("Example", "Extras"))
        self.assertEqual([m.key for m in obj.methods], ["- added", "+ make"])
        self.assertEqual(len(obj.properties), 1)
        self.assertEqual(runtime.diagnostics, [])

    def test_32_bit_class_and_method_layout(self):
        image = Image(pointer_size=4)
        methods = image.methods([("oldTarget", "v8@0:4", 0x2000)])
        cls = image.cls(methods=methods, data_flags=3)
        image.section("__objc_classlist", cls)
        runtime = ObjCRuntime(image).parse()
        self.assertEqual(runtime.classes[0].methods[0].types, "v8@0:4")
        self.assertEqual(runtime.diagnostics, [])

    def test_invalid_records_and_partial_section_do_not_abort_parse(self):
        image = Image()
        cls = image.cls()
        image.section("__objc_classlist", 0xBAD000, cls)
        name, start, end = image.section_list[0]
        image.section_list[0] = (name, start, end + 1)
        runtime = ObjCRuntime(image).parse()
        self.assertEqual(len(runtime.classes), 1)
        self.assertTrue(any("partial pointer" in warning for warning in runtime.diagnostics))
        self.assertTrue(any("class:" in warning for warning in runtime.diagnostics))

    def test_cancel_returns_partial_results_and_parse_can_be_repeated(self):
        image = Image()
        cls = image.cls()
        image.section("__objc_classlist", cls, cls)
        runtime = ObjCRuntime(image)
        image.cancelled = lambda: bool(runtime.classes)
        runtime.parse()
        self.assertTrue(runtime.cancelled)
        self.assertEqual(len(runtime.classes), 1)
        image.cancelled = lambda: False
        runtime.parse()
        self.assertFalse(runtime.cancelled)
        self.assertEqual(len(runtime.classes), 1)
        self.assertEqual(runtime.diagnostics, [])


if __name__ == "__main__":
    unittest.main()
