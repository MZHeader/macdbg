from __future__ import annotations

from functools import partial
from typing import List, Tuple

import lldb

from textual.command import Hit, Hits, Provider


def _complete(ci: lldb.SBCommandInterpreter, line: str) -> List[Tuple[str, str]]:
    matches = lldb.SBStringList()
    descs = lldb.SBStringList()
    ci.HandleCompletionWithDescriptions(line, len(line), 0, 200, matches, descs)
    out: List[Tuple[str, str]] = []
    for i in range(1, matches.GetSize()):
        name = matches.GetStringAtIndex(i).rstrip()
        desc = descs.GetStringAtIndex(i) if i < descs.GetSize() else ""
        if name:
            out.append((name, desc))
    return out


class LldbCommandProvider(Provider):
    @property
    def _ci(self) -> lldb.SBCommandInterpreter:
        return self.app.dbg.ci

    async def startup(self) -> None:
        self._top_level: List[Tuple[str, str]] = _complete(self._ci, "")

    async def search(self, query: str) -> Hits:
        query = query.strip()
        if " " in query:
            head, _, tail = query.rpartition(" ")
            candidates = _complete(self._ci, query)
            matcher = self.matcher(tail or query)
            for name, desc in candidates:
                full = "{} {}".format(head, name).strip()
                score = matcher.match(name) if tail else 1.0
                if score <= 0:
                    continue
                yield Hit(
                    score,
                    matcher.highlight(full) if tail else full,
                    partial(self._run, full),
                    help=desc or None,
                )
            return
        matcher = self.matcher(query)
        for name, desc in self._top_level:
            score = matcher.match(name) if query else 0.5
            if score <= 0:
                continue
            yield Hit(
                score,
                matcher.highlight(name) if query else name,
                partial(self._run, name),
                help=desc or None,
            )

    def _run(self, command: str) -> None:
        self.app._run_palette_command(command)
