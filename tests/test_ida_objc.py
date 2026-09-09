"""Exercise the IDA adapter without IDA or Qt, including sparse database bytes."""

import importlib.util
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


class Database:
    def __init__(self, bits=64, big_endian=False, modern_api=True):
        self.memory = {}
        self.segment_list = []
        self.fixups = {}
        self.names = {}
        self.read_calls = []
        self.cancelled = False
        self.bits = bits
        self.big_endian = big_endian
        self.modern_api = modern_api

    def write(self, ea, data):
        self.memory.update((ea + index, byte) for index, byte in enumerate(data))

    def segment(self, name, start, data, size=None):
        self.write(start, data)
        self.segment_list.append(SimpleNamespace(name=name, start_ea=start,
                                                 end_ea=start + (size or len(data))))
        self.segment_list.sort(key=lambda seg: seg.start_ea)

    def get_bytes_and_mask(self, ea, size, flags=1):
        self.read_calls.append((ea, size, flags))
        # IDAPython's wrapper keeps the requested buffer length even when its
        # C++ read stops at a hole. Nonzero filler catches trusting that tail.
        result = bytearray(b"\xAA" * size)
        mask = bytearray((size + 7) // 8)
        for index in range(size):
            if ea + index not in self.memory:
                if flags:
                    continue
                break
            result[index] = self.memory[ea + index]
            mask[index // 8] |= 1 << (index % 8)
        return bytes(result), bytes(mask)

    def getseg(self, ea):
        return next((s for s in self.segment_list if s.start_ea <= ea < s.end_ea), None)

    def reader_class(self):
        database = self

        def get_segment_info(out, ea):
            segment = database.getseg(ea)
            if segment is None:
                return False
            out.start_ea, out.end_ea = segment.start_ea, segment.end_ea
            return True

        class Fixup:
            def get(self, ea):
                value = database.fixups.get(ea)
                if value is None:
                    return False
                self.base, self.off, self.displacement, self.unused = value
                return True

            def get_base(self):
                return self.base

            def is_unused(self):
                return self.unused

        modules = {
            "ida_bytes": SimpleNamespace(get_bytes_and_mask=self.get_bytes_and_mask,
                                          is_loaded=lambda ea: ea in self.memory),
            "ida_fixup": SimpleNamespace(fixup_data_t=Fixup),
            "ida_ida": SimpleNamespace(inf_is_be=lambda: self.big_endian,
                                        inf_is_64bit=lambda: self.bits == 64,
                                        inf_is_32bit_exactly=lambda: self.bits == 32),
            "ida_idaapi": SimpleNamespace(BADADDR=(1 << 64) - 1),
            "ida_kernwin": SimpleNamespace(user_cancelled=lambda: self.cancelled),
            "ida_name": SimpleNamespace(get_name=lambda ea: self.names.get(ea, "")),
            "ida_segment": SimpleNamespace(
                get_first_seg=lambda: self.segment_list[0] if self.segment_list else None,
                get_next_seg=lambda ea: next((s for s in self.segment_list
                                             if s.start_ea > ea), None),
                get_segm_name=lambda segment: segment.name,
                getseg=self.getseg),
        }
        if self.modern_api:
            # Deliberately omit every deprecated function in the modern mock.
            modules["ida_segment"] = SimpleNamespace(
                segment_info_t=SimpleNamespace,
                get_segment_info=get_segment_info,
                get_segment_name=lambda ea: self.getseg(ea).name,
                get_first_segment_ea=lambda: self.segment_list[0].start_ea
                    if self.segment_list else (1 << 64) - 1,
                get_next_segment_ea=lambda ea: next((s.start_ea for s in self.segment_list
                                                    if s.start_ea > ea), (1 << 64) - 1))
        path = Path(__file__).resolve().parents[1] / "objc_explorer" / "ida_reader.py"
        spec = importlib.util.spec_from_file_location("_test_ida_reader", path)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, modules):
            spec.loader.exec_module(module)
        return module.IDAReader

    def reader(self):
        return self.reader_class()()


class IDAReaderTests(unittest.TestCase):
    def test_loaded_bytes_required_even_inside_segment(self):
        db = Database()
        db.segment("__data", 0x1000, b"abcd", size=64)
        db.write(0x1005, b"f")
        reader = db.reader()
        self.assertEqual(reader.read(0x1000, 4), b"abcd")
        self.assertFalse(reader.mapped(0x1000, 6))
        self.assertFalse(reader.mapped(0x1004, 1))
        self.assertFalse(reader.mapped(0, 1))
        with self.assertRaises(ValueError):
            reader.read(0x1000, 6)
        self.assertTrue(all(flags == 0 for _, _, flags in db.read_calls))

    def test_large_or_overflowing_reads_rejected_before_sdk_call(self):
        db = Database()
        reader = db.reader()
        self.assertFalse(reader.mapped(0x1000, reader.MAX_READ + 1))
        self.assertFalse(reader.mapped((1 << 64) - 4, 8))
        self.assertFalse(reader.mapped(-1, 8))
        self.assertFalse(reader.mapped(0x1000, -1))
        self.assertEqual(db.read_calls, [])

    def test_fixup_replaces_encoded_pointer_and_preserves_addend_flags(self):
        db = Database()
        db.write(0x1000, struct.pack("<Q", 0xAABB000000001234))
        db.fixups[0x1000] = (0x100000000, 0x2000, 3, False)
        self.assertEqual(db.reader().pointer(0x1000), 0x100002003)

    def test_import_target_need_not_contain_loaded_bytes(self):
        db = Database()
        db.write(0x1000, bytes(8))
        db.fixups[0x1000] = (0, 0x700000, 0, False)
        db.names[0x700000] = "_OBJC_CLASS_$_NSObject"
        reader = db.reader()
        self.assertEqual(reader.pointer(0x1000), 0x700000)
        self.assertEqual(reader.class_name(0x700000), "NSObject")
        self.assertFalse(reader.mapped(0x700000))

    def test_missing_unused_and_invalid_fixups_keep_raw_pointer(self):
        db = Database()
        db.write(0x1000, struct.pack("<Q", 0x9876))
        reader = db.reader()
        self.assertEqual(reader.pointer(0x1000), 0x9876)
        db.fixups[0x1000] = (0, 0x7000, 0, True)
        self.assertEqual(reader.pointer(0x1000), 0x9876)
        db.fixups[0x1000] = ((1 << 64) - 1, 0, 0, False)
        self.assertEqual(reader.pointer(0x1000), 0x9876)

    def test_32_bit_fixup_wraps_negative_displacement(self):
        db = Database(bits=32)
        db.write(0x1000, bytes(4))
        db.fixups[0x1000] = (0x1000, 0x30, -0x10, False)
        reader = db.reader()
        self.assertEqual(reader.pointer_size, 4)
        self.assertEqual(reader.pointer(0x1000), 0x1020)

    def test_string_may_end_before_uninitialized_bytes(self):
        db = Database()
        db.write(0x1000, "héllo".encode() + b"\0")
        self.assertEqual(db.reader().string(0x1000), "héllo")

    def test_string_limit_and_holes_fail_without_zero_filling(self):
        db = Database()
        db.write(0x1000, b"x" * 32)
        reader = db.reader()
        reader.MAX_STRING = 16
        with self.assertRaisesRegex(ValueError, "unterminated"):
            reader.string(0x1000)
        reader.MAX_STRING = 64
        with self.assertRaisesRegex(ValueError, "unmapped or truncated"):
            reader.string(0x1000)

    def test_image_flags_apply_to_owning_image_only(self):
        db = Database()
        db.segment("first:__objc_imageinfo", 0x1000, struct.pack("<II", 0, 0x40))
        db.segment("first:__objc_const", 0x2000, bytes(64))
        db.segment("second:__objc_imageinfo", 0x3000, bytes(8))
        db.segment("second:__objc_const", 0x4000, bytes(64))
        reader = db.reader()
        self.assertTrue(reader.category_class_properties(0x2008))
        self.assertFalse(reader.category_class_properties(0x4008))
        self.assertFalse(reader.category_class_properties(0x9000))

    def test_macho_segment_prefix_is_not_an_image_name(self):
        db = Database()
        db.segment("__DATA_CONST:__objc_imageinfo", 0x1000, struct.pack("<II", 0, 0x40))
        db.segment("__DATA:__objc_const", 0x2000, bytes(64))
        self.assertTrue(db.reader().category_class_properties(0x2008))

    @staticmethod
    def modern_cache(version=2, mapping_offset=0x200):
        db = Database()
        header = bytearray(0x200)
        header[:16] = b"dyld_v1  arm64e\0"
        struct.pack_into("<I", header, 0x10, mapping_offset)
        struct.pack_into("<QQ", header, 0x1D0, 0x1000, 0x48)
        opts = bytearray(0x48)
        struct.pack_into("<I", opts, 0, version)
        struct.pack_into("<Q", opts, 0x30, 0x2000)
        db.segment("DYLD_CACHE_HEADER", 0x100000000, header)
        db.segment("objc_opts", 0x100001000, opts)
        db.segment("selectors", 0x100002000, b"selector\0")
        return db

    def test_modern_cache_base_is_relative_to_header(self):
        for version in (1, 2):
            db = self.modern_cache(version=version)
            self.assertEqual(db.reader().relative_selector_base(), 0x100002000)

    def test_unknown_truncated_and_unloaded_cache_bases_are_not_guessed(self):
        self.assertIsNone(self.modern_cache(version=99).reader().relative_selector_base())
        self.assertIsNone(self.modern_cache(mapping_offset=0x100).reader().relative_selector_base())
        db = self.modern_cache()
        del db.memory[0x100002000]
        self.assertIsNone(db.reader().relative_selector_base())

    def test_legacy_v16_selector_base_uses_signed_struct_relative_offset(self):
        db = Database()
        opts = bytearray(0x30)
        struct.pack_into("<I", opts, 0, 16)
        struct.pack_into("<q", opts, 0x28, -0x1000)
        db.segment("libobjc:__objc_opt_ro", 0x2000, opts)
        db.segment("selectors", 0x1000, b"selector\0")
        self.assertEqual(db.reader().relative_selector_base(), 0x1000)
        db.write(0x2000, struct.pack("<I", 15))
        self.assertIsNone(db.reader().relative_selector_base())

    def test_cancellation_and_segment_snapshot(self):
        db = Database()
        db.segment("__objc_classlist", 0x1000, bytes(8))
        reader = db.reader()
        self.assertEqual(list(reader.segments()), [("__objc_classlist", 0x1000, 0x1008)])
        self.assertFalse(reader.cancelled())
        db.cancelled = True
        self.assertTrue(reader.cancelled())

    def test_segment_api_fallback_and_cached_image_lookup(self):
        for modern_api in (False, True):
            db = Database(modern_api=modern_api)
            db.segment("sample:__objc_imageinfo", 0x1000, struct.pack("<II", 0, 0x40))
            db.segment("sample:__objc_const", 0x2000, bytes(32))
            reader = db.reader()
            self.assertEqual(list(reader.segments()), [
                ("sample:__objc_imageinfo", 0x1000, 0x1008),
                ("sample:__objc_const", 0x2000, 0x2020)])
            # Classification must depend only on the captured ranges, without
            # making getseg/get_segment_info calls for each category.
            db.segment_list.clear()
            self.assertTrue(reader.category_class_properties(0x2000))
            self.assertTrue(reader.category_class_properties(0x201F))
            self.assertFalse(reader.category_class_properties(0x2020))
            self.assertFalse(reader.category_class_properties(0x1800))
            self.assertFalse(reader.category_class_properties(0x800))

    def test_unsupported_architecture_rejected(self):
        for db in (Database(bits=16), Database(big_endian=True)):
            with self.assertRaises(ValueError):
                db.reader()


if __name__ == "__main__":
    unittest.main()
