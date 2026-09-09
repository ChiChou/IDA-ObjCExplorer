"""Objective-C metadata browser for IDA 9.x (Python 3)."""
import os
import sys

import ida_idaapi
import ida_pro
import ida_kernwin as kw
import ida_bytes

# IDA may load plugins without adding their directory to sys.path.
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
if _MODULE_DIR not in sys.path:
    sys.path.insert(0, _MODULE_DIR)

from objc_explorer.ida_reader import IDAReader
from objc_explorer.runtime import ObjCRuntime

PLUGIN_NAME = 'ObjCExplorer'


class ClassDump(ObjCRuntime):
    """Script entry point; parsed methods retain selectors and type encodings."""
    def __init__(self, output=None, verbose=False, reader=None):
        super().__init__(reader or IDAReader())
        self.output = output
        self.verbose = verbose

    def parse(self):
        super().parse()
        if self.output is not None or self.verbose:
            self.write(self.output or sys.stdout)
        return self

    def write(self, output):
        """Write an inspection dump; raw encodings are not C declarations."""
        print('// Objective-C metadata dump (raw type encodings)', file=output)
        if self.cancelled:
            print('// Partial results: parsing was cancelled', file=output)
        for kind, objects in (('class', self.classes), ('protocol', self.protocols),
                              ('category', self.categories)):
            for obj in objects:
                if kind == 'class':
                    declaration = '@interface ' + obj.name
                    if obj.superclass:
                        declaration += ' : ' + obj.superclass
                elif kind == 'category':
                    declaration = '@interface %s (%s)' % (obj.class_name or '<unresolved>', obj.name)
                else:
                    declaration = '@protocol ' + obj.name
                if obj.protocols:
                    declaration += ' <' + ', '.join(obj.protocols) + '>'
                print(declaration, file=output)
                for prop in obj.properties:
                    print('  property %s%s // %s' % ('+ ' if prop.is_class else '',
                                                   prop.name, prop.attributes), file=output)
                for ivar in getattr(obj, 'ivars', []):
                    print('  ivar %s // %s, offset %s' % (ivar.name, ivar.types, ivar.offset), file=output)
                optional = False
                for method in obj.methods:
                    if kind == 'protocol' and optional != method.optional:
                        optional = method.optional
                        print('@optional' if optional else '@required', file=output)
                    print('  %s // %s%s' % (method.key, method.types,
                          ' @ 0x%X' % method.imp if method.imp else ''), file=output)
                print('@end\n', file=output)
        for diagnostic in self.diagnostics:
            print('// ' + diagnostic, file=output)


def export(data=None, path=None):
    """Export a new UTF-8 dump, replacing a confirmed destination."""
    path = path or kw.ask_file(True, '*.txt', 'Save Objective-C metadata dump')
    if not path:
        return False
    if data is None:
        kw.show_wait_box('Building Objective-C metadata')
        try:
            data = ClassDump().parse()
        finally:
            kw.hide_wait_box()
    try:
        with open(path, 'w', encoding='utf-8') as output:
            data.write(output)
    except OSError as exc:
        kw.warning('Could not save Objective-C dump: %s' % exc)
        return False
    kw.msg('[%s] Exported %s\n' % (PLUGIN_NAME, path))
    return True


class _ExportDumpAction(kw.action_handler_t):
    def __init__(self, data):
        super().__init__()
        self.data = data

    def activate(self, ctx):
        export(self.data)
        return 1

    def update(self, ctx):
        return kw.AST_ENABLE_ALWAYS


class _NativeChooser(kw.Choose):
    """Native IDA widgets avoid depending on a particular Python Qt binding."""
    def __init__(self, title, columns, data, on_close=None):
        super().__init__(title, columns, flags=kw.Choose.CH_RESTORE)
        self.data = data
        self.on_close = on_close

    def OnPopup(self, widget, popup_handle):
        action = kw.action_desc_t(None, 'Export dump…', _ExportDumpAction(self.data))
        kw.attach_dynamic_action_to_popup(None, popup_handle, action)

    def Show(self):
        if self.GetWidget() is not None:
            self.Activate()
            return True
        result = super().Show(modal=False)
        if result in (0, kw.Choose.ALREADY_EXISTS):
            return True
        self._unhook_popup()
        return False

    def _unhook_popup(self):
        # Choose.Show installs a popup hook whose weak reference must not outlive us.
        hook = getattr(self, 'ui_hooks_trampoline', None)
        if hook is not None:
            hook.unhook()
            self.ui_hooks_trampoline = None

    def OnClose(self):
        self._unhook_popup()
        if self.on_close is not None:
            callback, self.on_close = self.on_close, None
            callback(self)


def _object_name(kind, obj):
    if kind == 'Category':
        return '%s (%s)' % (obj.class_name or '<unresolved>', obj.name)
    return obj.name


class MemberView(_NativeChooser):
    def __init__(self, data, kind, obj, on_close=None):
        self.kind = kind
        self.obj = obj
        title = '%s: %s @ %X' % (PLUGIN_NAME, _object_name(kind, obj)[:80], obj.ea)
        super().__init__(title, [['Kind', 16], ['Name', 48], ['Address', 18],
                                ['Type encoding / attributes', 64]], data, on_close)
        self.rows = []
        for method in obj.methods:
            label = 'Class method' if method.is_class else 'Method'
            key = method.key + (' [optional]' if method.optional else '')
            self.rows.append((label, key, method.imp or method.ea, method.types))
        for prop in obj.properties:
            label = 'Class property' if prop.is_class else 'Property'
            self.rows.append((label, prop.name, prop.ea, prop.attributes))
        for ivar in getattr(obj, 'ivars', []):
            offset = 'unknown' if ivar.offset is None else str(ivar.offset)
            self.rows.append(('Ivar', ivar.name, ivar.ea,
                              '%s; offset %s' % (ivar.types, offset)))
        details = getattr(obj, 'superclass', '')
        if obj.protocols:
            details += ('; ' if details else '') + 'Protocols: ' + ', '.join(obj.protocols)
        self.rows.append(('Metadata', _object_name(kind, obj), obj.ea, details))

    def OnGetSize(self):
        return len(self.rows)

    def OnGetLine(self, n):
        kind, name, ea, detail = self.rows[n]
        return [kind, name, '0x%X' % ea if ea else '', detail]

    def OnSelectLine(self, n):
        if 0 <= n < len(self.rows):
            ea = self.rows[n][2]
            if ea and ea != ida_idaapi.BADADDR and ida_bytes.is_mapped(ea):
                kw.jumpto(ea)
            elif ea:
                kw.warning('Address 0x%X is not loaded in this database.' % ea)
        return (kw.Choose.NOTHING_CHANGED,)


class ClassView(_NativeChooser):
    def __init__(self, data, on_close=None):
        super().__init__(PLUGIN_NAME, [['Kind', 12], ['Name', 48], ['Address', 18],
                                       ['Details', 64]], data, on_close)
        self.objects = [(kind, obj) for kind, objects in
                        (('Class', data.classes), ('Protocol', data.protocols),
                         ('Category', data.categories)) for obj in objects]
        self.member_views = {}
        self.rows = []
        for kind, obj in self.objects:
            details = '%d methods, %d properties' % (len(obj.methods), len(obj.properties))
            if getattr(obj, 'superclass', ''):
                details = obj.superclass + '; ' + details
            self.rows.append([kind, _object_name(kind, obj), '0x%X' % obj.ea, details])
        if data.cancelled:
            self.rows.append(['Status', 'Partial results: parsing was cancelled', '', ''])
        for diagnostic in data.diagnostics:
            self.rows.append(['Diagnostic', diagnostic, '', ''])
        if not self.rows:
            self.rows.append(['Status', 'No Objective-C metadata found', '', ''])

    def OnGetSize(self):
        return len(self.rows)

    def OnGetLine(self, n):
        return self.rows[n]

    def _member_closed(self, view):
        key = (view.kind, view.obj.ea)
        if self.member_views.get(key) is view:
            del self.member_views[key]

    def OnSelectLine(self, n):
        if 0 <= n < len(self.objects):
            kind, obj = self.objects[n]
            key = (kind, obj.ea)
            view = self.member_views.get(key)
            if view is None:
                view = MemberView(self.data, kind, obj, self._member_closed)
                self.member_views[key] = view
            if not view.Show():
                self.member_views.pop(key, None)
                kw.warning('Could not open Objective-C members.')
        return (kw.Choose.NOTHING_CHANGED,)

    def OnClose(self):
        views = list(self.member_views.values())
        self.member_views.clear()
        for view in views:
            view.Close()
        super().OnClose()


class ExplorerSession(ida_idaapi.plugmod_t):
    def __init__(self):
        super().__init__()
        self.view = None

    def _closed(self, view):
        if self.view is view:
            self.view = None

    def run(self, arg):
        if self.view is not None:
            return self.view.Show()
        kw.show_wait_box('Building Objective-C metadata')
        try:
            data = ClassDump().parse()
        except Exception as exc:
            kw.warning('Could not read Objective-C metadata: %s' % exc)
            return False
        finally:
            kw.hide_wait_box()
        for diagnostic in data.diagnostics:
            kw.msg('[%s] %s\n' % (PLUGIN_NAME, diagnostic))
        self.view = ClassView(data, self._closed)
        if not self.view.Show():
            self.view = None
            kw.warning('Could not open Objective-C explorer.')
            return False
        return True


class ObjCExplorer(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    comment = 'Inspect Objective-C classes, protocols and categories'
    help = comment
    wanted_name = PLUGIN_NAME
    wanted_hotkey = 'Ctrl-Shift-E'

    def init(self):
        if ida_pro.IDA_SDK_VERSION < 900:
            return ida_idaapi.PLUGIN_SKIP
        return ExplorerSession()


def PLUGIN_ENTRY():
    return ObjCExplorer()


# File > Script file is useful for testing without installing the plugin.
if __name__ == '__main__':
    _objc_explorer_session = ExplorerSession()
    _objc_explorer_session.run(0)
