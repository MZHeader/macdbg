from __future__ import annotations

from typing import Callable, List, Optional, Tuple

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, Label, OptionList
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
    ) -> None:
        super().__init__()
        self._items = items
        self._x, self._y = x, y

    def compose(self) -> ComposeResult:
        opts = [Option(" " + label + " ", id=str(i)) for i, (label, _) in enumerate(self._items)]
        yield OptionList(*opts, id="menu_list")

    def on_mount(self) -> None:
        menu = self.query_one("#menu_list", OptionList)
        longest = max(len(lbl) for lbl, _ in self._items)
        width = longest + 10
        height = len(self._items) + 2
        screen_w, screen_h = self.app.size
        x = min(self._x, max(0, screen_w - width))
        y = min(self._y, max(0, screen_h - height))
        menu.styles.offset = (x, y)
        menu.styles.width = width
        menu.styles.height = height
        menu.focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        idx = int(event.option.id or "0")
        _, callback = self._items[idx]
        self.dismiss(None)
        self.app.call_after_refresh(callback)

    def on_click(self, event) -> None:
        menu = self.query_one("#menu_list", OptionList)
        if event.widget is not menu and menu not in getattr(event.widget, "ancestors", []):
            self.dismiss(None)


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
