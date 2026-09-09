"""IDA database reader for :mod:`objc_explorer.runtime`, with no Qt dependency.

IDA's Mach-O loader owns rebasing, chained fixups and authenticated pointers.
Use its fixup targets instead of guessing a pointer format from high bits.
This reader never changes bytes, fixups, names or analysis in the database.
"""

from bisect import bisect_right

import ida_bytes
import ida_fixup
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_name
import ida_segment


class IDAReader:
    """A bounded, read-only snapshot of the current database's section layout."""

    MAX_READ = 1024 * 1024
    MAX_STRING = 64 * 1024

    def __init__(self):
        if ida_ida.inf_is_be():
            raise ValueError("Only little-endian Objective-C 2 images are supported")
        if ida_ida.inf_is_64bit():
            self.pointer_size = 8
        elif ida_ida.inf_is_32bit_exactly():
            self.pointer_size = 4
        else:
            raise ValueError("Objective-C metadata requires a 32- or 64-bit database")
        self._pointer_mask = (1 << (8 * self.pointer_size)) - 1
        self._segments = []
        if hasattr(ida_segment, "get_segment_info"):
            ea = ida_segment.get_first_segment_ea()
            while ea != ida_idaapi.BADADDR:
                segment = ida_segment.segment_info_t()
                if ida_segment.get_segment_info(segment, ea):
                    self._segments.append((ida_segment.get_segment_name(ea),
                                           segment.start_ea, segment.end_ea))
                ea = ida_segment.get_next_segment_ea(ea)
        else:
            # Earlier IDA 9 versions expose segment_t rather than snapshots.
            segment = ida_segment.get_first_seg()
            while segment is not None:
                self._segments.append((ida_segment.get_segm_name(segment),
                                       segment.start_ea, segment.end_ea))
                segment = ida_segment.get_next_seg(segment.start_ea)
        self._segment_starts = [start for _, start, _ in self._segments]
        self._image_flags = self._find_image_flags()
        self._selector_base = self._find_selector_base()

    def _valid_range(self, ea, size):
        return (isinstance(ea, int) and isinstance(size, int) and
                0 < ea < ida_idaapi.BADADDR and 0 <= size <= self.MAX_READ and
                ea + size <= ida_idaapi.BADADDR)

    def read(self, ea, size):
        if not self._valid_range(ea, size):
            raise ValueError("invalid or oversized metadata read")
        if not size:
            return b""
        data = self._read_prefix(ea, size)
        if len(data) != size:
            raise ValueError("unmapped or truncated metadata at 0x%X" % ea)
        return data

    @staticmethod
    def _read_prefix(ea, size):
        # The Python wrapper can return a full-size buffer after a partial C++
        # read. Its initialized-byte mask, not buffer length, proves validity.
        result = ida_bytes.get_bytes_and_mask(ea, size, 0)
        if result is None:
            return b""
        data, mask = result
        loaded = 0
        for byte in mask:
            if loaded >= min(size, len(data)):
                break
            width = min(8, size - loaded, len(data) - loaded)
            if byte == 0xFF:
                loaded += width
                continue
            # Check at most eight bytes in the first partial mask octet. This
            # also avoids depending on the SDK bitmap's bit numbering order.
            for _ in range(width):
                if not ida_bytes.is_loaded(ea + loaded):
                    return data[:loaded]
                loaded += 1
        return data[:loaded]

    def mapped(self, ea, size=1):
        try:
            self.read(ea, size)
            return True
        except (ValueError, RuntimeError, OverflowError):
            return False

    def pointer(self, ea):
        raw = int.from_bytes(self.read(ea, self.pointer_size), "little")
        fixup = ida_fixup.fixup_data_t()
        try:
            if not fixup.get(ea) or fixup.is_unused():
                return raw
            base, offset = fixup.get_base(), fixup.off
            if (base == ida_idaapi.BADADDR or offset == ida_idaapi.BADADDR or
                    base < 0 or offset < 0):
                return raw
            # SDK fixup.hpp defines target as get_base()+off. Displacement is
            # the addend from that target; retain low class-data/list tags.
            value = (base + offset + fixup.displacement) & self._pointer_mask
            return raw if value == self._pointer_mask else value
        except (RuntimeError, TypeError, ValueError, OverflowError):
            return raw

    def string(self, ea):
        if not self._valid_range(ea, 1):
            raise ValueError("invalid string address")
        result = bytearray()
        while len(result) < self.MAX_STRING:
            cursor = ea + len(result)
            if not self._valid_range(cursor, 1):
                break
            size = min(256, self.MAX_STRING - len(result),
                       ida_idaapi.BADADDR - cursor)
            # A valid terminator may precede an uninitialized hole. Only scan
            # the initialized prefix, never undefined bytes in the SDK buffer.
            data = self._read_prefix(cursor, size)
            if not data:
                raise ValueError("unmapped or truncated string at 0x%X" % cursor)
            end = data.find(b"\0")
            if end >= 0:
                result.extend(data[:end])
                return result.decode("utf-8", errors="replace")
            result.extend(data)
        raise ValueError("unterminated string exceeds %d bytes" % self.MAX_STRING)

    def segments(self):
        return iter(self._segments)

    def cancelled(self):
        return bool(ida_kernwin.user_cancelled())

    @staticmethod
    def _image_key(name):
        parts = name.split(":")
        if len(parts) == 1:
            return ""
        prefix = parts[:-1]
        # Some loaders retain Mach-O segment names before section names.
        if prefix[-1] in ("__TEXT", "__DATA", "__DATA_CONST", "__DATA_DIRTY",
                           "__AUTH", "__AUTH_CONST", "__OBJC"):
            prefix.pop()
        return ":".join(prefix)

    def _image_at(self, ea):
        index = bisect_right(self._segment_starts, ea) - 1
        if index >= 0:
            name, _, end = self._segments[index]
            if ea < end:
                return self._image_key(name)
        return None

    def _find_image_flags(self):
        result = {}
        for name, start, end in self._segments:
            if name.rsplit(":", 1)[-1] != "__objc_imageinfo" or end - start < 8:
                continue
            try:
                flags = int.from_bytes(self.read(start + 4, 4), "little")
                key = self._image_key(name)
                # Conflicting metadata is ambiguous; only enable a field when
                # every image-info record for the image declares it present.
                result[key] = result.get(key, flags) & flags
            except ValueError:
                continue
        return result

    def category_class_properties(self, ea):
        # objc_image_info::HasCategoryClassProperties, in objc-runtime-new.h.
        return bool(self._image_flags.get(self._image_at(ea), 0) & 0x40)

    def class_name(self, ea):
        """Recover external classes whose metadata isn't loaded in this IDB."""
        if not isinstance(ea, int) or not 0 < ea < ida_idaapi.BADADDR:
            return ""
        name = ida_name.get_name(ea) or ""
        for prefix in ("_OBJC_CLASS_$_", "OBJC_CLASS_$_"):
            if name.startswith(prefix):
                return name[len(prefix):]
        return ""

    def relative_selector_base(self, method_list_ea=None):
        return self._selector_base

    def _find_selector_base(self):
        """Read validated modern cache headers or legacy objc_opt_t version 16.

        ABI sources (Apple dyld): include/mach-o/dyld_cache_format.h,
        common/DyldSharedCache.h, common/DyldSharedCache.cpp and
        include/objc-shared-cache.h. Offsets are VM-relative, not file-relative.
        Missing/unloaded cache components leave the base unavailable.
        """
        candidates = set()
        if self._segments:
            candidates.add(self._segments[0][1])
        for name, start, _ in self._segments:
            if name.rsplit(":", 1)[-1] == "DYLD_CACHE_HEADER":
                candidates.add(start)
        for start in sorted(candidates):
            try:
                header = self.read(start, 0x20)
                if not header.startswith(b"dyld_v"):
                    continue
                mapping_offset = int.from_bytes(header[0x10:0x14], "little")
                # mappingOffset bounds which header fields this version has.
                if mapping_offset < 0x1E0:
                    continue
                fields = self.read(start + 0x1D0, 16)
                opt_offset = int.from_bytes(fields[:8], "little")
                opt_size = int.from_bytes(fields[8:], "little")
                if not opt_offset or opt_size < 0x38:
                    continue
                opts = self.read(start + opt_offset, 0x38)
                if int.from_bytes(opts[:4], "little") not in (1, 2):
                    continue
                base_offset = int.from_bytes(opts[0x30:0x38], "little")
                base = start + base_offset
                if base_offset and self.mapped(base, 1):
                    return base
            except (ValueError, RuntimeError, OverflowError):
                continue
        for name, start, end in self._segments:
            if name.rsplit(":", 1)[-1] != "__objc_opt_ro" or end - start < 0x30:
                continue
            try:
                opts = self.read(start, 0x30)
                if int.from_bytes(opts[:4], "little") != 16:
                    continue
                offset = int.from_bytes(opts[0x28:0x30], "little", signed=True)
                base = start + offset
                if offset and self.mapped(base, 1):
                    return base
            except (ValueError, RuntimeError, OverflowError):
                continue
        return None
