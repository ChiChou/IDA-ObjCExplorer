"""Native chooser behavior without an IDA installation or Python Qt binding.

The mock implements only the chooser lifecycle used by the frontend. Actual
widget creation and popup interaction are covered by the IDA GUI smoke test.
"""

import builtins
import importlib.util
from pathlib import Path
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from objc_explorer.runtime import Method, Property, Ivar, ObjCClass, ObjCProtocol, ObjCCategory


class NativeHost:
    def __init__(self):
        class Choose:
            CH_RESTORE = 1
            ALREADY_EXISTS = -3
            NOTHING_CHANGED = 0

            def __init__(self, title, cols, flags=0):
                self.title = title
                self.cols = cols
                self.widget = None
                self.activations = 0
                self.ui_hooks_trampoline = None

            def GetWidget(self):
                return self.widget

            def Show(self, modal=False):
                self.widget = object()
                self.ui_hooks_trampoline = SimpleNamespace(unhook=Mock())
                return 0

            def Activate(self):
                self.activations += 1

            def Close(self):
                self.widget = None
                self.OnClose()

        self.kw = ModuleType("ida_kernwin")
        self.kw.Choose = Choose
        self.kw.action_handler_t = object
        self.kw.AST_ENABLE_ALWAYS = 1
        self.kw.action_desc_t = lambda name, label, handler: SimpleNamespace(
            name=name, label=label, handler=handler)
        for name in ("attach_dynamic_action_to_popup", "jumpto", "warning", "msg",
                     "show_wait_box", "hide_wait_box"):
            setattr(self.kw, name, Mock())
        self.kw.ask_file = Mock(return_value=None)
        self.modules = {
            "ida_kernwin": self.kw,
            "ida_pro": SimpleNamespace(IDA_SDK_VERSION=940),
            "ida_idaapi": SimpleNamespace(plugmod_t=object, plugin_t=object,
                                           PLUGIN_MULTI=1, PLUGIN_SKIP=0,
                                           BADADDR=(1 << 64) - 1),
            "ida_bytes": SimpleNamespace(is_mapped=lambda ea: 0x1000 <= ea < 0x6000),
            "objc_explorer.ida_reader": SimpleNamespace(IDAReader=object),
        }

    def load_plugin(self):
        path = Path(__file__).resolve().parents[1] / "ObjCExplore.py"
        spec = importlib.util.spec_from_file_location("_test_frontend", path)
        module = importlib.util.module_from_spec(spec)
        original_import = builtins.__import__

        def without_qt(name, *args, **kwargs):
            if name.startswith(("PyQt", "PySide")):
                raise AssertionError("The native frontend must not import Qt: " + name)
            return original_import(name, *args, **kwargs)

        # Restore both module and path state, including when importing fails.
        original_path = sys.path[:]
        try:
            with patch.dict(sys.modules, self.modules), patch("builtins.__import__", without_qt):
                spec.loader.exec_module(module)
        finally:
            sys.path[:] = original_path
        return module


class FrontendTests(unittest.TestCase):
    def setUp(self):
        self.host = NativeHost()
        self.plugin = self.host.load_plugin()
        self.data = self.plugin.ClassDump(reader=SimpleNamespace(pointer_size=8))
        self.obj = ObjCClass(
            "Example", 0x1000,
            methods=[Method("run:", "v24@0:8@16", 0x2000, 0x1100),
                     Method("required", "v@:", 0, 0x1200, optional=True)],
            properties=[Property("value", "T@,N,V_value", 0x1300)],
            ivars=[Ivar("_value", "@", 0x1400)],
            protocols=["ExampleProtocol"], superclass="NSObject")
        self.data.classes = [self.obj]
        self.data.protocols = [ObjCProtocol("ExampleProtocol", 0x3000)]
        self.data.categories = [ObjCCategory("Extras", 0x4000, class_name="Example")]

    def test_native_import_does_not_leak_mock_modules(self):
        before = {name: sys.modules.get(name) for name in self.host.modules}
        module = self.host.load_plugin()
        self.assertTrue(issubclass(module.ClassView, self.host.kw.Choose))
        self.assertIsInstance(module.PLUGIN_ENTRY().init(), module.ExplorerSession)
        self.assertEqual(before, {name: sys.modules.get(name) for name in self.host.modules})

    def test_method_jump_uses_implementation_then_metadata(self):
        view = self.plugin.MemberView(self.data, "Class", self.obj)
        view.OnSelectLine(0)
        view.OnSelectLine(1)
        self.assertEqual([call.args[0] for call in self.host.kw.jumpto.call_args_list],
                         [0x2000, 0x1200])
        self.assertIn("optional", view.OnGetLine(1)[1])
        self.host.kw.warning.assert_not_called()

    def test_unmapped_member_cannot_jump(self):
        self.obj.methods[0].imp = 0x8000
        view = self.plugin.MemberView(self.data, "Class", self.obj)
        view.OnSelectLine(0)
        view.OnSelectLine(-1)
        view.OnSelectLine(view.OnGetSize())
        self.host.kw.jumpto.assert_not_called()
        self.assertIn("0x8000", self.host.kw.warning.call_args.args[0])

    def test_metadata_retains_raw_types_and_unknown_offsets(self):
        view = self.plugin.MemberView(self.data, "Class", self.obj)
        rows = [view.OnGetLine(n) for n in range(view.OnGetSize())]
        self.assertEqual(rows[0][3], "v24@0:8@16")
        self.assertEqual(next(row[3] for row in rows if row[0] == "Property"), "T@,N,V_value")
        self.assertIn("offset unknown", next(row[3] for row in rows if row[0] == "Ivar"))
        self.assertIn("ExampleProtocol", next(row[3] for row in rows if row[0] == "Metadata"))

    def test_session_focuses_existing_view_and_closes_owned_members(self):
        parser = Mock()
        parser.parse.return_value = self.data
        session = self.plugin.ExplorerSession()
        with patch.object(self.plugin, "ClassDump", return_value=parser) as factory:
            self.assertTrue(session.run(0))
            view = session.view
            self.assertTrue(session.run(0))
            self.assertIs(session.view, view)
            self.assertEqual(view.activations, 1)
            factory.assert_called_once()
            parser.parse.assert_called_once()
            view.OnSelectLine(0)
            member = next(iter(view.member_views.values()))
            view.OnSelectLine(0)
            self.assertEqual(member.activations, 1)
            self.assertEqual(len(view.member_views), 1)
            main_hook, member_hook = view.ui_hooks_trampoline, member.ui_hooks_trampoline
            view.Close()
            self.assertIsNone(session.view)
            self.assertFalse(view.member_views)
            self.assertIsNone(member.GetWidget())
            main_hook.unhook.assert_called_once()
            member_hook.unhook.assert_called_once()
            self.assertTrue(session.run(0))
            self.assertIsNot(session.view, view)

    def test_closing_member_allows_reopen_without_losing_main_view(self):
        view = self.plugin.ClassView(self.data)
        view.Show()
        view.OnSelectLine(0)
        member = next(iter(view.member_views.values()))
        member.Close()
        self.assertFalse(view.member_views)
        self.assertIsNotNone(view.GetWidget())
        view.OnSelectLine(0)
        self.assertIsNot(next(iter(view.member_views.values())), member)

    def test_failed_chooser_creation_releases_popup_hook_and_session_view(self):
        created = []
        hook = SimpleNamespace(unhook=Mock())

        def failed_show(view, modal=False):
            # The SDK installs this hook before attempting native creation.
            view.ui_hooks_trampoline = hook
            created.append(view)
            return -4  # Choose.NO_ATTR

        parser = Mock()
        parser.parse.return_value = self.data
        session = self.plugin.ExplorerSession()
        with patch.object(self.host.kw.Choose, "Show", failed_show), \
                patch.object(self.plugin, "ClassDump", return_value=parser):
            self.assertFalse(session.run(0))
        self.assertIsNone(session.view)
        self.assertIsNone(created[0].ui_hooks_trampoline)
        hook.unhook.assert_called_once()
        self.host.kw.warning.assert_called_once()

    def popup_action(self):
        view = self.plugin.ClassView(self.data)
        view.OnPopup(None, "popup")
        action = self.host.kw.attach_dynamic_action_to_popup.call_args.args[2]
        self.assertIn("Export dump", action.label)
        self.assertEqual(action.handler.update(None), self.host.kw.AST_ENABLE_ALWAYS)
        return action.handler

    def test_popup_export_cancel_does_not_parse_or_create_file(self):
        action = self.popup_action()
        with patch("builtins.open") as opening, patch.object(self.plugin, "ClassDump") as parser:
            self.assertEqual(action.activate(None), 1)
            opening.assert_not_called()
            parser.assert_not_called()
        self.host.kw.ask_file.assert_called_once()
        self.host.kw.warning.assert_not_called()

    def test_popup_exports_existing_snapshot_as_utf8(self):
        self.obj.name = "Exämple"
        action = self.popup_action()
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "dump.txt"
            self.host.kw.ask_file.return_value = str(destination)
            with patch.object(self.plugin, "ClassDump") as parser:
                self.assertEqual(action.activate(None), 1)
                parser.assert_not_called()
            exported = destination.read_text(encoding="utf-8")
        self.assertIn("@interface Exämple : NSObject", exported)
        self.assertIn("v24@0:8@16", exported)
        self.host.kw.warning.assert_not_called()

    def test_export_error_is_reported(self):
        with patch("builtins.open", side_effect=PermissionError("read-only destination")):
            self.assertFalse(self.plugin.export(self.data, "/unwritable/dump.txt"))
        self.assertIn("read-only destination", self.host.kw.warning.call_args.args[0])

    def test_failed_parse_releases_wait_box_and_does_not_open_view(self):
        session = self.plugin.ExplorerSession()
        with patch.object(self.plugin, "ClassDump", side_effect=ValueError("unsupported image")):
            self.assertFalse(session.run(0))
        self.assertIsNone(session.view)
        self.host.kw.hide_wait_box.assert_called_once()
        self.assertIn("unsupported image", self.host.kw.warning.call_args.args[0])

    def test_status_and_diagnostic_rows_do_not_open_members(self):
        self.data.cancelled = True
        self.data.diagnostics = ["0x1500: unavailable ivar offset"]
        view = self.plugin.ClassView(self.data)
        self.assertEqual(view.OnGetLine(2)[1], "Example (Extras)")
        for n in range(len(view.objects), view.OnGetSize()):
            view.OnSelectLine(n)
        self.assertFalse(view.member_views)
        rows = [view.OnGetLine(n) for n in range(view.OnGetSize())]
        self.assertTrue(any(row[0] == "Status" and "cancelled" in row[1] for row in rows))
        self.assertTrue(any(row[0] == "Diagnostic" and "0x1500" in row[1] for row in rows))
        self.data.classes = self.data.protocols = self.data.categories = []
        self.data.cancelled = False
        self.data.diagnostics = []
        empty = self.plugin.ClassView(self.data)
        self.assertEqual(empty.OnGetSize(), 1)
        empty.OnSelectLine(0)
        self.assertFalse(empty.member_views)


if __name__ == "__main__":
    unittest.main()
