from __future__ import annotations

from typing import Any, Callable, List, Optional, Tuple

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, Label, OptionList, TextArea
from textual.widgets.option_list import Option


class ContextMenu(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "close")]

    DEFAULT_CSS = """
    ContextMenu { align: left top; background: transparent; }
    ContextMenu > OptionList#menu_list {
        background: $panel;
        border: round $accent;
        padding: 0;
        scrollbar-size: 0 0;
    }
    ContextMenu > #menu_box {
        background: $panel;
        border: round $accent;
        padding: 0;
    }
    ContextMenu #menu_header {
        padding: 0 1;
        color: $text-muted;
        border-bottom: solid $accent;
    }
    ContextMenu > #menu_box > OptionList#menu_list {
        background: $panel;
        border: none;
        padding: 0;
        scrollbar-size: 0 0;
    }
    ContextMenu OptionList > .option-list--option {
        padding: 0 2;
    }
    ContextMenu OptionList > .option-list--option-highlighted {
        background: $accent;
        color: $text;
    }
    """

    def __init__(
        self,
        items: List[Tuple[str, Callable[[], None]]],
        x: int = 0,
        y: int = 0,
        on_dismiss: Optional[Callable[[], None]] = None,
        header: Optional[str] = None,
    ) -> None:
        super().__init__()
        self._items = items
        self._x, self._y = x, y
        self._on_dismiss = on_dismiss
        self._picked = False
        self._header = header

    def compose(self) -> ComposeResult:
        opts = [Option(" " + label + " ", id=str(i)) for i, (label, _) in enumerate(self._items)]
        if self._header:
            with Vertical(id="menu_box"):
                yield Label(self._header, id="menu_header")
                yield OptionList(*opts, id="menu_list")
        else:
            yield OptionList(*opts, id="menu_list")

    def on_mount(self) -> None:
        menu = self.query_one("#menu_list", OptionList)
        longest = max(len(lbl) for lbl, _ in self._items)
        screen_w, screen_h = self.app.size
        if self._header:
            box = self.query_one("#menu_box", Vertical)
            width = min(max(longest + 10, 48), max(20, screen_w - 2))
            header = self.query_one("#menu_header", Label)
            inner = max(1, width - 2)
            # The header Label has 0 1 padding, so its text area is two columns
            # narrower than the box interior; wrap to that or every line doubles.
            htext = max(1, width - 4)
            # Cap the preview so a huge command can never push the option list
            # off the bottom of the box and hide the last choice.
            capped = self._cap_lines(self._header, htext, self.MAX_HEADER_LINES)
            header.update(capped)
            header.styles.width = inner
            header_lines = self._wrapped_line_count(capped, htext)
            # Option list gets its full height; the box auto-sizes around header
            # plus list, so every option always renders.
            menu.styles.height = len(self._items)
            menu.styles.width = inner
            box.styles.width = width
            box.styles.height = "auto"
            height = len(self._items) + header_lines + 3
            x = min(self._x, max(0, screen_w - width))
            y = min(self._y, max(0, screen_h - height))
            box.styles.offset = (x, y)
        else:
            width = longest + 10
            height = len(self._items) + 2
            x = min(self._x, max(0, screen_w - width))
            y = min(self._y, max(0, screen_h - height))
            menu.styles.offset = (x, y)
            menu.styles.width = width
            menu.styles.height = height
        menu.focus()

    MAX_HEADER_LINES = 6

    @staticmethod
    def _wrapped_line_count(text: str, width: int) -> int:
        if width <= 0:
            return 1
        n = 0
        for line in text.split("\n"):
            n += max(1, -(-len(line) // width))
        return n

    @classmethod
    def _cap_lines(cls, text: str, width: int, max_lines: int) -> str:
        out: List[str] = []
        for line in text.split("\n"):
            while len(line) > width and len(out) < max_lines:
                out.append(line[:width])
                line = line[width:]
            if len(out) >= max_lines:
                break
            out.append(line)
        if len(out) >= max_lines and cls._wrapped_line_count(text, width) > max_lines:
            out = out[:max_lines]
            out[-1] = out[-1][: max(0, width - 2)] + " …"
        return "\n".join(out)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        idx = int(event.option.id or "0")
        _, callback = self._items[idx]
        self._picked = True
        self.dismiss(None)
        self.app.call_after_refresh(callback)

    def on_click(self, event) -> None:
        menu = self.query_one("#menu_list", OptionList)
        if event.widget is not menu and menu not in getattr(event.widget, "ancestors", []):
            self.dismiss(None)

    def dismiss(self, result=None):
        if not self._picked and self._on_dismiss is not None:
            self.app.call_after_refresh(self._on_dismiss)
            self._on_dismiss = None
        return super().dismiss(result)


class PromptScreen(ModalScreen[Optional[str]]):
    BINDINGS = [Binding("escape", "dismiss('')", "cancel")]

    DEFAULT_CSS = """
    PromptScreen { align: center middle; }
    PromptScreen > Vertical {
        width: 60; height: auto; background: $panel;
        border: solid $accent; padding: 1 2;
    }
    """

    def __init__(self, title: str, initial: str = "") -> None:
        super().__init__()
        self._title = title
        self._initial = initial

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self._title)
            yield Input(value=self._initial, id="prompt_input")

    def on_mount(self) -> None:
        self.query_one(Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)


class ToggleMenu(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "close")]

    DEFAULT_CSS = ContextMenu.DEFAULT_CSS

    def __init__(self, get_items, x: int = 0, y: int = 0) -> None:
        super().__init__()
        self._get_items = get_items
        self._x, self._y = x, y

    def compose(self) -> ComposeResult:
        yield OptionList(id="menu_list")

    def _repopulate(self) -> None:
        ol = self.query_one("#menu_list", OptionList)
        items = self._get_items()
        self._current = items
        ol.clear_options()
        for i, (label, _) in enumerate(items):
            ol.add_option(Option(" " + label + " ", id=str(i)))

    def on_mount(self) -> None:
        self._repopulate()
        items = self._current
        menu = self.query_one("#menu_list", OptionList)
        longest = max(len(lbl) for lbl, _ in items)
        width = longest + 10
        height = len(items) + 2
        screen_w, screen_h = self.app.size
        x = min(self._x, max(0, screen_w - width))
        y = min(self._y, max(0, screen_h - height))
        menu.styles.offset = (x, y)
        menu.styles.width = width
        menu.styles.height = height
        menu.focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        idx = int(event.option.id or "0")
        highlighted = event.option_list.highlighted
        _, callback = self._current[idx]
        callback()
        self._repopulate()
        try:
            self.query_one(OptionList).highlighted = highlighted
        except Exception:
            pass

    def on_click(self, event) -> None:
        menu = self.query_one("#menu_list", OptionList)
        if event.widget is not menu and menu not in getattr(event.widget, "ancestors", []):
            self.dismiss(None)


class MultilineEditor(ModalScreen[Optional[str]]):
    BINDINGS = [
        Binding("escape", "dismiss('')", "cancel"),
        Binding("ctrl+s", "save", "save"),
    ]

    DEFAULT_CSS = """
    MultilineEditor { align: center middle; }
    MultilineEditor > Vertical {
        width: 90%; height: 70%; background: $panel;
        border: solid $accent; padding: 1 2;
    }
    MultilineEditor TextArea { height: 1fr; }
    """

    def __init__(self, title: str, initial: str = "") -> None:
        super().__init__()
        self._title = title
        self._initial = initial

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self._title)
            yield TextArea.code_editor(self._initial, id="editor")

    def on_mount(self) -> None:
        self.query_one(TextArea).focus()

    def action_save(self) -> None:
        self.dismiss(self.query_one(TextArea).text)
