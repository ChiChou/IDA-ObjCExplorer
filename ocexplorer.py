import struct

import idaapi
import ida_segment
import ida_bytes
import ida_nalt
import ida_idaapi

import ida_kernwin as kw
from idaapi import PluginForm
from PyQt5 import QtWidgets, QtGui


PLUGIN_NAME = 'ObjCExplorer'


def cstr(ea):
    try:
        return ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C).decode()
    except Exception as e:
        print('Unable to decode string at %s' % hex(ea))
        raise e


class Objc2Class(object):
    """
    struct __objc2_class
    {
        __objc2_class *isa;
        __objc2_class *superclass;
        void *cache;
        void *vtable;
        __objc2_class_ro *info;
    };
    """
    fmt = '<QQQQQ'
    length = struct.calcsize(fmt)

    def __init__(self, data, offset=0):
        (self.isa,
         self.superclass,
         self.cache,
         self.vtable,
         self.info) = struct.unpack_from(self.fmt, data, offset)


class Objc2ClassRo(object):
    """
    struct __objc2_class_ro
    {
        uint32_t flags;
        uint32_t ivar_base_start;
        uint32_t ivar_base_size;
        uint32_t reserved;
        void *ivar_lyt;
        char *name;
        __objc2_meth_list *base_meths;
        __objc2_prot_list *base_prots;
        __objc2_ivar_list *ivars;
        void *weak_ivar_lyt;
        __objc2_prop_list *base_props;
    };
    """
    fmt = '<IIIIQQQQQQQ'
    length = struct.calcsize(fmt)

    def __init__(self, data, offset=0):
        (self.flags,
         self.ivar_base_start,
         self.ivar_base_size,
         self.reserved,
         self.ivar_lyt,
         self.name,
         self.base_meths,
         self.base_prots,
         self.ivars,
         self.weak_ivar_lyt,
         self.base_props) = struct.unpack_from(self.fmt, data, offset)


class Objc2Method(object):
    fmt = '<QQQ'
    length = struct.calcsize(fmt)

    def __init__(self, data, offset=0):
        (self.name, self.types, self.imp) = struct.unpack_from(
            self.fmt, data, offset)


def method_list(ea):
    if not ea:
        return

    count = ida_bytes.get_dword(ea + 4)
    first = ea + 8
    for i in range(count):
        ea_method_t = first + i * Objc2Method.length
        data = ida_bytes.get_bytes(ea_method_t, Objc2Method.length)
        yield Objc2Method(data)


class Base(object):
    def __init__(self, name, ea):
        self.name = name
        self.ea = ea

    def __repr__(self):
        return '<%s "%s">' % (self.__class__.__name__, self.name)


class Clazz(Base):
    def __init__(self, name, ea):
        super().__init__(name, ea)
        self.methods = {}


class Protocol(Base):
    def __init__(self, name, ea):
        super().__init__(name, ea)
        self.methods = []


class ClassDump(object):
    def __init__(self, output=None, verbose=False):
        self.classes = []
        self.protocols = []
        self.class_lookup = {}
        self.protocol_lookup = {}
        self.lookup = {}
        self.output = output
        self.verbose = verbose

    def print(self, *args):
        if self.output is not None:
            print(*args, file=self.output)
        elif self.verbose:
            print(*args)

    def parse(self):
        if ida_segment.get_segm_by_name('DYLD_CACHE_HEADER'):
            seg = ida_segment.get_first_seg()

            def handle(seg):
                name = ida_segment.get_segm_name(seg)
                try:
                    mod, segname = name.split(':')
                except ValueError:
                    return

                if segname == '__objc_protolist':
                    self.handle_proto_seg(seg)
                elif segname == '__objc_classlist':
                    self.handle_class_seg(seg)

            while seg:
                handle(seg)
                seg = ida_segment.get_next_seg(seg.start_ea)

            return

        protocols = ida_segment.get_segm_by_name('__objc_protolist')
        if protocols:
            self.handle_proto_seg(protocols)

        classes = ida_segment.get_segm_by_name('__objc_classlist')
        if classes:
            self.handle_class_seg(classes)

    def handle_proto_seg(self, protocols):
        for ea in range(protocols.start_ea, protocols.end_ea, 8):
            self.handle_protocol(ea)

            if len(self.protocols) > 4096:
                print('Threshold exceed')
                break

    def handle_class_seg(self, classes):
        for ea in range(classes.start_ea, classes.end_ea, 8):
            self.handle_class(ea)

            if len(self.classes) > 4096:
                print('Threshold exceed')
                break

    def handle_protocol(self, ea):
        protocol_ea = ida_bytes.get_qword(ea)
        protocol_name = cstr(ida_bytes.get_qword(protocol_ea + 8))
        method_list_ea = ida_bytes.get_qword(protocol_ea + 3 * 8)
        p = Protocol(protocol_name, ea=protocol_ea)
        self.print('@protocol', protocol_name)
        # todo: support class methods
        for method in method_list(method_list_ea):
            key = '- ' + cstr(method.name)
            p.methods.append(key)
            self.print(key)
        self.print('@end')
        self.print()
        self.protocols.append(p)
        self.protocol_lookup[p.name] = p
        self.lookup[ea] = p

    def handle_class(self, ea):
        clazz_ea = ida_bytes.get_qword(ea)
        clazz = Objc2Class(ida_bytes.get_bytes(clazz_ea, Objc2Class.length))
        # if clazz.info & 7 != 0:
        # swift

        meta_class = Objc2Class(
            ida_bytes.get_bytes(clazz.isa, Objc2Class.length))
        meta_class.info = (meta_class.info >> 3) << 3
        meta_info = Objc2ClassRo(ida_bytes.get_bytes(
            meta_class.info, Objc2ClassRo.length))

        clazz.info = (clazz.info >> 3) << 3
        clazz_info = Objc2ClassRo(ida_bytes.get_bytes(
            clazz.info, Objc2ClassRo.length))

        c = Clazz(cstr(clazz_info.name), ea=clazz_ea)

        self.print('@interface', cstr(clazz_info.name))
        for method in method_list(meta_info.base_meths):
            key = '+ ' + cstr(method.name)
            c.methods[key] = method.imp
            self.print(key)

        for method in method_list(clazz_info.base_meths):
            key = '- ' + cstr(method.name)
            c.methods[key] = method.imp
            self.print(key)

        self.print('@end')
        self.print()

        self.classes.append(c)
        self.class_lookup[c.name] = c
        self.lookup[ea] = c


class ClassView(PluginForm):
    # todo: classref
    cols = ['Name', 'Address']

    def __init__(self):
        super(ClassView, self).__init__()
        self.data = None
        self.tree = None

    def dblclick(self, item):
        '''Handle double click event.'''
        try:
            idaapi.jumpto(int(item.text(1), 16))
        except:
            pass

    def load_data(self):
        kw.show_wait_box('Building class information')
        classdump = ClassDump()
        classdump.parse()
        kw.hide_wait_box()

        self.data = classdump

        class_root = QtWidgets.QTreeWidgetItem(self.tree)
        class_root.setText(0, 'Classes')
        class_root.setExpanded(True)

        x = lambda ea: '0x%X' % ea

        for clazz in self.data.classes:
            item = QtWidgets.QTreeWidgetItem(class_root)
            item.setText(0, clazz.name)
            item.setText(1, x(clazz.ea))

            for method, imp in clazz.methods.items():
                child = QtWidgets.QTreeWidgetItem(item)
                child.setText(0, method)
                child.setText(1, x(imp))

        protocol_root = QtWidgets.QTreeWidgetItem(self.tree)
        protocol_root.setText(0, 'Protocols')
        
        # todo: refactor
        for proto in self.data.protocols:
            item = QtWidgets.QTreeWidgetItem(protocol_root)
            item.setText(0, proto.name)
            item.setText(1, x(proto.ea))

            for method in proto.methods:
                child = QtWidgets.QTreeWidgetItem(item)
                child.setText(0, method)
                # todo:
                child.setText(1, x(proto.ea))


    def OnCreate(self, form):
        '''Called when the plugin form is created'''

        self.parent = self.FormToPyQtWidget(form)

        self.tree = QtWidgets.QTreeWidget()
        self.tree.setColumnCount(len(self.cols))
        self.tree.setHeaderLabels(self.cols)
        self.tree.itemDoubleClicked.connect(self.dblclick)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.tree)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        self.load_data()

        self.tree.setColumnWidth(0, 512)
        self.tree.setColumnWidth(1, 512)
        self.parent.setLayout(layout)

    def OnClose(self, form):
        '''Called when the plugin form is closed.'''
        del self

    def Show(self):
        '''Creates the form is not created or focuses it if it was.'''
        return PluginForm.Show(self, 'ClassDump')


class ObjCExplorer(ida_idaapi.plugin_t):
    """Class that is required for the code to be recognized as
    a plugin by IDA."""
    flags = 0
    comment = "classdump"
    help = comment
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Ctrl-Shift-E"

    def is_compatible(self):
        return idaapi.IDA_SDK_VERSION >= 700

    def init(self):
        return (ida_idaapi.PLUGIN_OK if
                self.is_compatible() else ida_idaapi.PLUGIN_SKIP)

    def run(self, arg):
        view = ClassView()
        view.Show()

    def term(self):
        pass


    # path = kw.ask_file(0, '*.txt', 'Save to')
    # if not path:
    #     print('Cancelled')
    #     return

    # with open(path, 'a') as fp:
    #     classdump = ClassDump(output=fp)
    #     classdump.parse()

    # for clazz in classdump.classes:
    #     print(clazz.name)


def PLUGIN_ENTRY():
    return ObjCExplorer()
