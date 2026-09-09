"""Read Objective-C 2 metadata from an image supplied by a reader.

The reader owns address translation, dyld fixups and pointer authentication. It
provides read(ea, size), pointer(ea), string(ea), mapped(ea, size), segments(), and
pointer_size (4 or 8). Segment records are (name, start, end). Optional
cancelled() supports UI cancellation. relative_selector_base may be an integer
or a callable accepting a method-list address; None selects the older relative
selector representation. The base applies only to lists flagged as using direct
selectors (or direct types). Cache readers must supply it for caches using a
shared selector base. No IDA or Qt imports are needed here.

ABI references:
https://github.com/apple-oss-distributions/objc4/blob/main/runtime/objc-runtime-new.h
https://github.com/apple-oss-distributions/objc4/blob/main/runtime/PointerUnion.h
https://github.com/apple-oss-distributions/dyld/blob/main/common/ObjCVisitor.cpp
"""

from dataclasses import dataclass, field


SMALL_METHOD_LIST = 0x80000000
DIRECT_SELECTORS = 0x40000000
DIRECT_TYPES = 0x20000000
METHOD_ENTRY_SIZE_MASK = 0x0000FFFC


class MetadataError(ValueError):
    pass


class ParseCancelled(Exception):
    pass


@dataclass
class Method:
    name: str
    types: str
    imp: int
    ea: int
    is_class: bool = False
    optional: bool = False
    name_ea: int = 0
    types_ea: int = 0

    @property
    def key(self):
        return ("+ " if self.is_class else "- ") + self.name


@dataclass
class Property:
    name: str
    attributes: str
    ea: int
    is_class: bool = False


@dataclass
class Ivar:
    name: str
    types: str
    ea: int
    offset: object = None
    size: int = 0
    alignment: int = 0


@dataclass
class ObjCClass:
    name: str
    ea: int
    methods: list = field(default_factory=list)
    properties: list = field(default_factory=list)
    ivars: list = field(default_factory=list)
    protocols: list = field(default_factory=list)
    superclass_ea: int = 0
    superclass: str = ""
    data_flags: int = 0
    ro_flags: int = 0
    instance_size: int = 0

    @property
    def is_swift(self):
        return bool(self.data_flags & 3)


@dataclass
class ObjCProtocol:
    name: str
    ea: int
    methods: list = field(default_factory=list)
    properties: list = field(default_factory=list)
    protocols: list = field(default_factory=list)


@dataclass
class ObjCCategory:
    name: str
    ea: int
    class_name: str = ""
    class_ea: int = 0
    methods: list = field(default_factory=list)
    properties: list = field(default_factory=list)
    protocols: list = field(default_factory=list)


class ObjCRuntime:
    """Resilient static parser. parse() returns self, including partial results.

    diagnostics contains address-prefixed strings suitable for an output pane.
    cancelled is true if a user interrupted parsing. Invalid records do not
    prevent subsequent records or sections from being inspected.
    """

    def __init__(self, reader, max_entries=100000, max_total_entries=1000000):
        self.reader = reader
        self.pointer_size = reader.pointer_size
        if self.pointer_size not in (4, 8):
            raise ValueError("Objective-C metadata requires 4- or 8-byte pointers")
        self.max_entries = max_entries
        self.max_total_entries = max_total_entries
        self._reset()

    def _reset(self):
        self.classes = []
        self.protocols = []
        self.categories = []
        self.class_lookup = {}
        self.protocol_lookup = {}
        self.category_lookup = {}
        self.lookup = {}
        self.diagnostics = []
        self.cancelled = False
        self._class_by_ea = {}
        self._protocol_by_ea = {}
        self._category_by_ea = {}
        self._entries_read = 0

    def _warn(self, ea, message):
        if len(self.diagnostics) < 1000:
            self.diagnostics.append("0x%X: %s" % (ea, message))
        elif len(self.diagnostics) == 1000:
            self.diagnostics.append("Further metadata diagnostics suppressed")

    def _check_cancelled(self):
        callback = getattr(self.reader, "cancelled", None)
        if callback and callback():
            raise ParseCancelled()

    def _mapped(self, ea, size):
        return ea > 0 and size >= 0 and bool(self.reader.mapped(ea, size))

    def _read(self, ea, size):
        if not self._mapped(ea, size):
            raise MetadataError("unmapped or truncated metadata (%d bytes)" % size)
        try:
            data = self.reader.read(ea, size)
        except Exception as exc:
            raise MetadataError("could not read metadata: %s" % exc) from exc
        if data is None or len(data) != size:
            raise MetadataError("short metadata read (%d bytes requested)" % size)
        return data

    def _uint(self, ea, size=4, signed=False):
        return int.from_bytes(self._read(ea, size), "little", signed=signed)

    def _pointer(self, ea):
        if not self._mapped(ea, self.pointer_size):
            raise MetadataError("unmapped or truncated pointer")
        try:
            value = self.reader.pointer(ea)
        except Exception as exc:
            raise MetadataError("could not resolve pointer: %s" % exc) from exc
        if not isinstance(value, int) or value < 0:
            raise MetadataError("reader returned an invalid pointer")
        return value

    def _string(self, ea, required=False):
        if not ea and not required:
            return ""
        if not self._mapped(ea, 1):
            raise MetadataError("unresolved string pointer 0x%X" % ea)
        try:
            value = self.reader.string(ea)
        except Exception as exc:
            raise MetadataError("could not read string at 0x%X: %s" % (ea, exc)) from exc
        if not isinstance(value, str) or (required and not value):
            raise MetadataError("missing string at 0x%X" % ea)
        return value

    def _entries(self, first, count, stride, minimum):
        if stride < minimum or stride > 65536:
            raise MetadataError("invalid entry size %d (minimum %d)" % (stride, minimum))
        if count > self.max_entries:
            self._warn(first, "entry count %d exceeds limit %d; list truncated" %
                       (count, self.max_entries))
            count = self.max_entries
        for index in range(count):
            self._check_cancelled()
            if self._entries_read >= self.max_total_entries:
                raise MetadataError("total metadata entry limit reached")
            ea = first + index * stride
            if not self._mapped(ea, minimum):
                self._warn(ea, "truncated list; remaining entries skipped")
                break
            self._entries_read += 1
            yield ea

    def _list_addresses(self, value):
        """Resolve a class_ro_t PointerUnion, including preattached categories."""
        if not value:
            return
        if not value & 1:
            yield value
            return
        ea = value & ~1
        try:
            stride = self._uint(ea)
            count = self._uint(ea + 4)
            seen = set()
            for entry in self._entries(ea + 8, count, stride, 8):
                packed = self._uint(entry, 8)
                offset = packed >> 16
                if offset & (1 << 47):
                    offset -= 1 << 48
                target = entry + offset
                if target == ea or target in seen:
                    self._warn(entry, "duplicate or self-referencing list skipped")
                    continue
                seen.add(target)
                if not self._mapped(target, 8):
                    self._warn(entry, "relative list target 0x%X is not loaded" % target)
                    continue
                yield target
        except MetadataError as exc:
            self._warn(ea, str(exc))

    def methods(self, value, is_class=False, optional=False):
        result = []
        for ea in self._list_addresses(value):
            try:
                flags = self._uint(ea)
                count = self._uint(ea + 4)
                small = bool(flags & SMALL_METHOD_LIST)
                direct_types = bool(flags & DIRECT_TYPES)
                direct = bool(flags & (DIRECT_SELECTORS | DIRECT_TYPES))
                stride = flags & METHOD_ENTRY_SIZE_MASK
                minimum = 12 if small else 3 * self.pointer_size
                base = getattr(self.reader, "relative_selector_base", None)
                if callable(base):
                    base = base(ea)
                if small and direct_types and base is None:
                    raise MetadataError("shared-cache selector/type base is unavailable")
                for entry in self._entries(ea + 8, count, stride, minimum):
                    try:
                        if small:
                            if direct and base is not None:
                                # Cache buffer offsets are unsigned; field-relative
                                # offsets in the original representation are signed.
                                name_ea = base + self._uint(entry)
                            else:
                                name_ea = entry + self._uint(entry, signed=True)
                                if not direct:
                                    name_ea = self._pointer(name_ea)
                            if direct_types:
                                types_ea = base + self._uint(entry + 4)
                            else:
                                types_offset = self._uint(entry + 4, signed=True)
                                types_ea = entry + 4 + types_offset if types_offset else 0
                            imp_offset = self._uint(entry + 8, signed=True)
                            # dyld's static visitor treats zero offsets as absent
                            # implementations, as emitted for protocol methods.
                            imp = entry + 8 + imp_offset if imp_offset else 0
                        else:
                            name_ea = self._pointer(entry)
                            types_ea = self._pointer(entry + self.pointer_size)
                            imp = self._pointer(entry + 2 * self.pointer_size)
                        name = self._string(name_ea, required=True)
                        try:
                            types = self._string(types_ea)
                        except MetadataError as exc:
                            self._warn(entry, str(exc))
                            types = ""
                        result.append(Method(name, types, imp, entry, is_class,
                                             optional, name_ea, types_ea))
                    except MetadataError as exc:
                        self._warn(entry, str(exc))
            except MetadataError as exc:
                self._warn(ea, str(exc))
        return result

    def properties(self, value, is_class=False):
        result = []
        for ea in self._list_addresses(value):
            try:
                stride, count = self._uint(ea), self._uint(ea + 4)
                for entry in self._entries(ea + 8, count, stride, 2 * self.pointer_size):
                    try:
                        name = self._string(self._pointer(entry), required=True)
                        attributes = self._string(self._pointer(entry + self.pointer_size))
                        result.append(Property(name, attributes, entry, is_class))
                    except MetadataError as exc:
                        self._warn(entry, str(exc))
            except MetadataError as exc:
                self._warn(ea, str(exc))
        return result

    def ivars(self, ea):
        result = []
        if not ea:
            return result
        try:
            stride, count = self._uint(ea), self._uint(ea + 4)
            for entry in self._entries(ea + 8, count, stride, 3 * self.pointer_size + 8):
                try:
                    offset_ea = self._pointer(entry)
                    name = self._string(self._pointer(entry + self.pointer_size))
                    types = self._string(self._pointer(entry + 2 * self.pointer_size))
                    alignment = self._uint(entry + 3 * self.pointer_size)
                    size = self._uint(entry + 3 * self.pointer_size + 4)
                    offset = None
                    if offset_ea:
                        try:
                            offset = self._uint(offset_ea, signed=True)
                        except MetadataError as exc:
                            # Swift can place offset storage in zero-fill sections
                            # and initialize it at runtime. Keep the declaration
                            # even when its static offset is unavailable.
                            self._warn(entry, "ivar offset at 0x%X unavailable: %s" %
                                       (offset_ea, exc))
                    if alignment == 0xFFFFFFFF:
                        alignment = self.pointer_size
                    elif alignment < 32:
                        alignment = 1 << alignment
                    else:
                        self._warn(entry, "invalid ivar alignment")
                        alignment = 0
                    result.append(Ivar(name, types, entry, offset, size, alignment))
                except MetadataError as exc:
                    self._warn(entry, str(exc))
        except MetadataError as exc:
            self._warn(ea, str(exc))
        return result

    def _protocol_names(self, value):
        result = []
        for ea in self._list_addresses(value):
            try:
                count = self._uint(ea, self.pointer_size)
                for entry in self._entries(ea + self.pointer_size, count,
                                           self.pointer_size, self.pointer_size):
                    try:
                        protocol_ea = self._pointer(entry)
                        name = self._string(self._pointer(protocol_ea + self.pointer_size),
                                            required=True)
                        if name not in result:
                            result.append(name)
                    except MetadataError as exc:
                        self._warn(entry, str(exc))
            except MetadataError as exc:
                self._warn(ea, str(exc))
        return result

    def _class_ro(self, ea):
        self._read(ea, 5 * self.pointer_size)
        data = self._pointer(ea + 4 * self.pointer_size)
        # DEBUG_DATA_MASK from objc4: remove low Swift/RR bits and high flags.
        mask = 0x00007FFFFFFFFFF8 if self.pointer_size == 8 else 0xFFFFFFFC
        ro = data & mask
        first_pointer = 16 if self.pointer_size == 8 else 12
        self._read(ro, first_pointer + 7 * self.pointer_size)
        flags = self._uint(ro)
        if flags & 0x80000000:
            raise MetadataError("realized class_rw_t metadata is not a static class_ro_t")
        return {
            "name": self._string(self._pointer(ro + first_pointer + self.pointer_size),
                                 required=True),
            "methods": self._pointer(ro + first_pointer + 2 * self.pointer_size),
            "protocols": self._pointer(ro + first_pointer + 3 * self.pointer_size),
            "ivars": self._pointer(ro + first_pointer + 4 * self.pointer_size),
            "properties": self._pointer(ro + first_pointer + 6 * self.pointer_size),
            "flags": flags, "size": self._uint(ro + 8),
            "data_flags": data & (7 if self.pointer_size == 8 else 3),
        }

    def _class_name(self, ea):
        if ea in self._class_by_ea:
            return self._class_by_ea[ea].name
        if self._mapped(ea, 5 * self.pointer_size):
            try:
                return self._class_ro(ea)["name"]
            except MetadataError:
                pass
        # Imported superclasses/category targets may exist only as loader symbols.
        resolve_name = getattr(self.reader, "class_name", None)
        if ea and callable(resolve_name):
            try:
                name = resolve_name(ea)
                if isinstance(name, str):
                    return name
            except Exception as exc:
                self._warn(ea, "could not resolve external class name: %s" % exc)
        return ""

    def parse_class(self, ea):
        if ea in self._class_by_ea:
            return self._class_by_ea[ea]
        try:
            info = self._class_ro(ea)
            obj = ObjCClass(info["name"], ea)
            self._class_by_ea[ea] = obj
            self.classes.append(obj)
            self.class_lookup[obj.name] = obj
            self.lookup[ea] = obj
            obj.data_flags = info["data_flags"]
            obj.ro_flags = info["flags"]
            obj.instance_size = info["size"]
            obj.superclass_ea = self._pointer(ea + self.pointer_size)
            obj.superclass = self._class_name(obj.superclass_ea)
            meta_ea = self._pointer(ea)
            if meta_ea:
                try:
                    meta = self._class_ro(meta_ea)
                    obj.methods.extend(self.methods(meta["methods"], is_class=True))
                    obj.properties.extend(self.properties(meta["properties"], is_class=True))
                except MetadataError as exc:
                    self._warn(meta_ea, "metaclass: %s" % exc)
            obj.methods.extend(self.methods(info["methods"]))
            obj.properties.extend(self.properties(info["properties"]))
            obj.ivars = self.ivars(info["ivars"])
            obj.protocols = self._protocol_names(info["protocols"])
            return obj
        except MetadataError as exc:
            self._warn(ea, "class: %s" % exc)
            return None

    def parse_protocol(self, ea):
        if ea in self._protocol_by_ea:
            return self._protocol_by_ea[ea]
        try:
            p = self.pointer_size
            self._read(ea, 8 * p + 8)
            name = self._string(self._pointer(ea + p), required=True)
            size = self._uint(ea + 8 * p)
            if size < 8 * p + 8:
                raise MetadataError("invalid protocol size %d" % size)
            obj = ObjCProtocol(name, ea)
            self._protocol_by_ea[ea] = obj
            self.protocols.append(obj)
            self.protocol_lookup[name] = obj
            self.lookup[ea] = obj
            for slot, is_class, optional in ((3, False, False), (4, True, False),
                                               (5, False, True), (6, True, True)):
                obj.methods.extend(self.methods(self._pointer(ea + slot * p),
                                                is_class, optional))
            obj.protocols = self._protocol_names(self._pointer(ea + 2 * p))
            obj.properties = self.properties(self._pointer(ea + 7 * p))
            class_properties_offset = 10 * p + 8
            if size >= class_properties_offset + p:
                obj.properties.extend(self.properties(self._pointer(ea + class_properties_offset),
                                                       is_class=True))
            return obj
        except MetadataError as exc:
            self._warn(ea, "protocol: %s" % exc)
            return None

    def parse_category(self, ea):
        if ea in self._category_by_ea:
            return self._category_by_ea[ea]
        try:
            p = self.pointer_size
            self._read(ea, 6 * p)
            name = self._string(self._pointer(ea), required=True)
            class_ea = self._pointer(ea + p)
            obj = ObjCCategory(name, ea, self._class_name(class_ea), class_ea)
            self._category_by_ea[ea] = obj
            self.categories.append(obj)
            self.category_lookup[(obj.class_name, name, ea)] = obj
            self.lookup[ea] = obj
            obj.methods = self.methods(self._pointer(ea + 2 * p))
            obj.methods.extend(self.methods(self._pointer(ea + 3 * p), is_class=True))
            obj.protocols = self._protocol_names(self._pointer(ea + 4 * p))
            obj.properties = self.properties(self._pointer(ea + 5 * p))
            # The optional class-properties field is gated by image-info flags,
            # not mapping alone: older category records have no size field.
            has_class_properties = getattr(self.reader, "category_class_properties", False)
            if callable(has_class_properties):
                has_class_properties = has_class_properties(ea)
            if has_class_properties:
                obj.properties.extend(self.properties(self._pointer(ea + 6 * p),
                                                       is_class=True))
            return obj
        except MetadataError as exc:
            self._warn(ea, "category: %s" % exc)
            return None

    def parse(self):
        self._reset()
        handlers = {
            "__objc_classlist": self.parse_class,
            "__objc_nlclslist": self.parse_class,
            "__objc_protolist": self.parse_protocol,
            "__objc_catlist": self.parse_category,
            "__objc_nlcatlist": self.parse_category,
            "__objc_catlist2": self.parse_category,
        }
        try:
            for name, start, end in self.reader.segments():
                self._check_cancelled()
                # IDA shared-cache modules prefix section names with image:.
                section = name.rsplit(":", 1)[-1]
                handler = handlers.get(section)
                if handler is None or end <= start:
                    continue
                count, remainder = divmod(end - start, self.pointer_size)
                if remainder:
                    self._warn(end - remainder, "partial pointer at end of %s" % name)
                try:
                    for slot in self._entries(start, count, self.pointer_size, self.pointer_size):
                        try:
                            target = self._pointer(slot)
                            if not target:
                                continue
                            obj = handler(target)
                            if obj is not None:
                                self.lookup[slot] = obj
                        except MetadataError as exc:
                            self._warn(slot, str(exc))
                except MetadataError as exc:
                    self._warn(start, str(exc))
        except ParseCancelled:
            self.cancelled = True
            self._warn(0, "parsing cancelled; results are partial")
        return self
