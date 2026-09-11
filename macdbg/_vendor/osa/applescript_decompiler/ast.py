from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional, Union, Dict, Any
import json

import warnings

import macdbg._vendor.osa.jinmo_applescript_disassembler.engine.runtimeobjects as rto
import macdbg._vendor.osa.jinmo_applescript_disassembler.engine.fasobjects.data_block as db

from macdbg._vendor.osa.applescript_decompiler.utils import *

EVENT_CODES = get_event_code_mapping()
SDEFS = load_sdefs_from_package()

INDENT_STR = "    "  # 4 spaces
DEFAULT_TARGET = "AppleScript Language"
STANDARD_ADDITIONS = "StandardAdditions"


class AppleScriptPrinter:
    target = DEFAULT_TARGET
    command = "None"
    analyzer = None

    def __init__(self, analyzer=None):
        if analyzer is not None:
            self.analyzer = analyzer(printer=self)

    def visit(self, node, indent: int = 0) -> str:
        if node is None:
            return ""
        method_name = "visit_" + node.__class__.__name__

        if self.analyzer is not None:
            if hasattr(self.analyzer, method_name):
                return getattr(self.analyzer, method_name)(node, indent)

        method = getattr(self, method_name, self.generic_visit)

        return method(node, indent)

    def generic_visit(self, node, indent: int = 0) -> str:
        # Fallback: useful while you’re still adding node types
        return f"<{node.__class__.__name__}>"

    def visit_Script(self, node: Script, indent: int = 0) -> str:
        parts: List[str] = []

        for prop in node.properties:
            parts.append(self.visit(prop, indent))

        for handler in node.handlers:
            if parts:
                parts.append("")  # blank line
            parts.append(self.visit(handler, indent))

        # any top-level body (script run section)
        for stmt in node.body:
            if parts:
                parts.append("")
            parts.append(self.visit(stmt, indent))

        return "\n".join(parts)

    def _i(self, indent: int) -> str:
        return INDENT_STR * indent

    def visit_Comment(self, node: Comment, indent: int = 0) -> str:
        return f"{self._i(indent)}-- {node.comment}"

    def visit_PropertyDecl(self, node: PropertyDecl, indent: int = 0) -> str:
        value_src = self.visit(node.initial_value, 0)
        return f"{self._i(indent)}property {node.name} : {value_src}"

    def visit_Handler(self, node: Handler, indent: int = 0) -> str:
        params = ""
        if node.parameters:
            params = "(" + ", ".join(node.parameters) + ")"

        _node_name = node.name

        if isinstance(_node_name, rto.Object):
            val = _node_name.value
            if isinstance(val, rto.EventIdentifier):
                _name = val.identifier[1].to_bytes(4, "big").decode("ascii")
                _node_name = EVENT_CODES[DEFAULT_TARGET].get(_name[:4], _name)
            else:
                _node_name = val.identifier[0].to_bytes(4, "big").decode(
                    "ascii"
                ) + val.identifier[1].to_bytes(4, "big").decode("ascii")

        header = f"{self._i(indent)}on {_node_name}{params}"

        body_lines = [self.visit(stmt, indent + 1) for stmt in node.body]
        body = "\n".join(body_lines) if body_lines else ""

        footer = f"{self._i(indent)}end {_node_name}"

        if body:
            return f"{header}\n{body}\n{footer}"
        else:
            return f"{header}\n{footer}"

    def visit_HandlerCall(self, node: HandlerCall, indent: int = 0) -> str:
        args = [self.visit(a, 0) for a in node.arguments]
        args_src = ", ".join([e if isinstance(e, str) else e.decode() for e in args])
        target_src = ""
        if node.target is not None:
            target_src = self.visit(node.target, 0)
            if target_src != "my":
                target_src = target_src + "'s"
            target_src = target_src + " "
        return f"{self._i(indent)}{target_src}{node.handler_name}({args_src})"

    def visit_SetStatement(self, node: SetStatement, indent: int = 0) -> str:
        target_src = self.visit(node.target, 0)
        value_src = self.visit(node.value, 0)
        return f"{self._i(indent)}set {target_src} to {value_src}"

    def visit_VariableDeclaration(
        self, node: VariableDeclaration, indent: int = 0
    ) -> str:
        kind = "global" if node.is_global else "local"
        names = ", ".join(node.names)
        return f"{self._i(indent)}{kind} {names}"

    def visit_IfStatement(self, node: IfStatement, indent: int = 0) -> str:
        cond_src = self.visit(node.condition, 0)
        header = f"{self._i(indent)}if {cond_src} then"

        then_lines = [self.visit(stmt, indent + 1) for stmt in node.then_block]
        then_block = "\n".join(then_lines)

        if node.else_block:
            else_lines = [self.visit(stmt, indent + 1) for stmt in node.else_block]
            else_block = "\n".join(else_lines)
            footer = f"{self._i(indent)}end if"
            return (
                f"{header}\n{then_block}\n{self._i(indent)}else\n{else_block}\n{footer}"
            )
        else:
            footer = f"{self._i(indent)}end if"
            return f"{header}\n{then_block}\n{footer}"

    def visit_RepeatStatement(self, node: RepeatStatement, indent: int = 0) -> str:
        k = node.kind
        if k is RepeatKind.FOREVER:
            header = f"{self._i(indent)}repeat"
        elif k is RepeatKind.WHILE:
            cond = self.visit(node.condition, 0)
            header = f"{self._i(indent)}repeat while {cond}"
        elif k is RepeatKind.UNTIL:
            cond = self.visit(node.condition, 0)
            header = f"{self._i(indent)}repeat until {cond}"
        elif k is RepeatKind.TIMES:
            times = self.visit(node.times, 0)
            header = f"{self._i(indent)}repeat {times} times"
        elif k is RepeatKind.WITH_COUNTER:
            frm = self.visit(node.from_expr, 0)
            to = self.visit(node.to_expr, 0)
            if node.by_expr:
                by = self.visit(node.by_expr, 0)
                _var = self.visit(node.counter_var, 0)
                header = (
                    f"{self._i(indent)}repeat with {_var} from {frm} to {to} by {by}"
                )
            else:
                header = f"{self._i(indent)}repeat with {_var} from {frm} to {to}"
        elif k is RepeatKind.WITH_IN:
            _in = self.visit(node.in_expr, 0)
            _var = self.visit(node.counter_var, 0)
            header = f"{self._i(indent)}repeat with {_var} in {_in}"
        else:
            header = f"{self._i(indent)}repeat"

        body_lines = [self.visit(stmt, indent + 1) for stmt in node.body]
        body = "\n".join(body_lines)
        footer = f"{self._i(indent)}end repeat"
        if body:
            return f"{header}\n{body}\n{footer}"
        else:
            return f"{header}\n{footer}"

    def visit_TryStatement(self, node: TryStatement, indent: int = 0) -> str:
        header = f"{self._i(indent)}try"
        try_lines = [self.visit(stmt, indent + 1) for stmt in node.try_block]
        try_block = "\n".join(try_lines)

        if node.on_error_block is not None:
            # note: we only stored one var; you can extend to hold number var too
            if node.on_error_var:
                on_line = f"{self._i(indent)}on error {node.on_error_var}"
            else:
                on_line = f"{self._i(indent)}on error"
            err_lines = [self.visit(stmt, indent + 1) for stmt in node.on_error_block]
            err_block = "\n".join(err_lines)
            footer = f"{self._i(indent)}end try"
            return f"{header}\n{try_block}\n{on_line}\n{err_block}\n{footer}"
        else:
            footer = f"{self._i(indent)}end try"
            return f"{header}\n{try_block}\n{footer}"

    def visit_TellBlock(self, node: TellBlock, indent: int = 0) -> str:
        target_src = self.visit(node.target, 0)

        prev_target = self.target
        self.target = target_src

        header = f"{self._i(indent)}tell {target_src}"
        body_lines = [self.visit(stmt, indent + 1) for stmt in node.body]
        body = "\n".join(body_lines)
        footer = f"{self._i(indent)}end tell"

        self.target = prev_target
        if body:
            return f"{header}\n{body}\n{footer}"
        else:
            return f"{header}\n{footer}"

    def visit_ReturnStatement(self, node: ReturnStatement, indent: int = 0) -> str:
        if node.value is None:
            return f"{self._i(indent)}return"
        return f"{self._i(indent)}return {self.visit(node.value, 0)}"

    def visit_ExitRepeat(self, node: ExitRepeat, indent: int = 0) -> str:
        return f"{self._i(indent)}exit repeat"

    def visit_ExprStatement(self, node: ExprStatement, indent: int = 0) -> str:
        return f"{self._i(indent)}{self.visit(node.expr, 0)}"

    def visit_LValue(self, node: LValue, indent: int = 0) -> str:
        return self.visit(node.obj)

    def visit_StringLiteral(self, node: StringLiteral, indent: int = 0) -> str:
        # naive quoting; you may want to escape quotes
        return json.dumps(node.value)

    def visit_Keyword(self, node: Keyword, indent: int = 0) -> str:
        # naive quoting; you may want to escape quotes

        if self.command != "None" and node.value in SDEFS[self.target][self.command]:
            params = SDEFS[self.target][node.command_name]["name"]
            if node.value in params:
                return params[node.value]["name"]

        if node.value in SDEFS[STANDARD_ADDITIONS]:
            return f"{SDEFS[STANDARD_ADDITIONS][node.value]['name']}"

        if node.value in EVENT_CODES[self.target]:
            return f"{EVENT_CODES[self.target][node.value]}"
        if node.value in EVENT_CODES[DEFAULT_TARGET]:
            return f"{EVENT_CODES[DEFAULT_TARGET][node.value]}"
        if (
            node.value[:4] in ["core", "misc"]
            and node.value[4:] in EVENT_CODES[DEFAULT_TARGET]
        ):
            return f"{EVENT_CODES[DEFAULT_TARGET][node.value[4:]]}"
        return f"{node.value}"

    def visit_NumberLiteral(self, node: NumberLiteral, indent: int = 0) -> str:
        return str(node.value)

    def visit_BooleanLiteral(self, node: BooleanLiteral, indent: int = 0) -> str:
        return "true" if node.value else "false"

    def visit_DateLiteral(self, node: DateLiteral, indent: int = 0) -> str:
        return f'date "{node.text}"'

    def visit_MissingValueLiteral(
        self, node: MissingValueLiteral, indent: int = 0
    ) -> str:
        return "missing value"

    def visit_VariableRef(self, node: VariableRef, indent: int = 0) -> str:
        return node.name

    def visit_ElementSpecifier(self, node: ElementSpecifier, indent: int = 0) -> str:
        container = self.visit(node.container, 0)
        if node.element_class:
            base = f"{node.element_class} of {container}"
        else:
            base = container
        if node.key is not None and node.key_kind is not None:
            key = self.visit(node.key, 0)
            return f"{base} whose {node.key_kind} is {key}"
        return base

    def visit_ListLiteral(self, node: ListLiteral, indent: int = 0) -> str:
        elems = ", ".join(self.visit(e, 0) for e in node.elements)
        return "{" + elems + "}"

    def visit_RecordField(self, node: RecordField, indent: int = 0) -> str:
        return f"{self.visit(node.label, 0)}: {self.visit(node.value, 0)}"

    def visit_RecordLiteral(self, node: RecordLiteral, indent: int = 0) -> str:
        fields = ", ".join(self.visit(f, 0) for f in node.fields)
        return "{" + fields + "}"

    # ---- Binary / Unary ops ------------------------------------------

    def visit_BinaryOp(self, node: BinaryOp, indent: int = 0) -> str:
        left = self.visit(node.left, 0)
        right = self.visit(node.right, 0)
        op = self._binop_to_src(node.op)
        if node.op is BinaryOpKind.COERCE:
            # x as type
            return f"({left} as {right})"
        elif node.op is BinaryOpKind.THRU:
            # alternatively f"{left}'s {right}"
            return f"{left} thru {right}"
        elif node.op is BinaryOpKind.GET_INDEXED:
            # alternatively f"{left}'s {right}"
            if right == "__it__" or right == "my":
                return left
            return f"{left} {right}"
        elif node.op is BinaryOpKind.GET_PROPERTY:
            # alternatively f"{left}'s {right}"
            if right == "__it__" or right == "my":
                return left
            return f"({left} of {right})"
        elif node.op is BinaryOpKind.EVERY:
            if left == "__it__":
                return f" every {right}"
            return f"(every {right} of {left})"
        return f"{left} {op} {right}"

    def _binop_to_src(self, op: BinaryOpKind) -> str:
        mapping = {
            BinaryOpKind.ADD: "+",
            BinaryOpKind.SUB: "-",
            BinaryOpKind.MUL: "*",
            BinaryOpKind.DIV: "/",
            BinaryOpKind.MOD: "mod",
            BinaryOpKind.POW: "^",
            BinaryOpKind.CONCAT: "&",
            BinaryOpKind.EQ: "is",
            BinaryOpKind.NE: "is not",
            BinaryOpKind.LT: "<",
            BinaryOpKind.LE: "≤",
            BinaryOpKind.GT: ">",
            BinaryOpKind.GE: "≥",
            BinaryOpKind.CONTAINS: "contains",
            BinaryOpKind.COERCE: "as",  # handled specially
            BinaryOpKind.GET_PROPERTY: "'s",  # handled specially
            BinaryOpKind.GET_INDEXED: "_",    # handled specially
            BinaryOpKind.AND: "and",
            BinaryOpKind.OR: "or",
        }
        return mapping.get(op, "unknown")

    def visit_UnaryOp(self, node: UnaryOp, indent: int = 0) -> str:
        operand = self.visit(node.operand, 0)
        if node.op is UnaryOpKind.NEG:
            return f"-({operand})"
        elif node.op is UnaryOpKind.NOT:
            return f"not ({operand})"
        elif node.op is UnaryOpKind.END_OF:
            return f"end of ({operand})"
        return operand

    def visit_CommandCall(self, node: CommandCall, indent: int = 0) -> str:
        prev_command = self.command
        prev_target = self.target

        if node.target is not None:
            self.target = self.visit(node.target, 0)

        _command_name = node.command_name
        if node.command_name in SDEFS[self.target]:
            self.command = _command_name
            _command_name = f"{SDEFS[self.target][node.command_name]['name']}"
        elif node.command_name in SDEFS[STANDARD_ADDITIONS]:
            self.command = _command_name
            self.target = STANDARD_ADDITIONS
            _command_name = f"{SDEFS[STANDARD_ADDITIONS][node.command_name]['name']}"
        elif node.command_name[4:] in EVENT_CODES[DEFAULT_TARGET]:
            _command_name = f"{EVENT_CODES[DEFAULT_TARGET][node.command_name[4:]]}"

        args_src = [self.visit(arg, 0) for arg in node.arguments]
        if args_src and args_src[0] == "__it__":
            args_src = args_src[1:]
        args_str = " ".join([e if isinstance(e, str) else e.decode() for e in args_src])
        target_prefix = ""
        if node.target is not None:
            target_prefix = f"tell application \"{self.visit(node.target, 0)}\" "

        self.command = prev_command
        self.target = prev_target

        return f"{self._i(indent)}({target_prefix}{_command_name} {args_str})"


@dataclass
class Node:
    def to_source(self, analyzer=None, indent: int = 0) -> str:
        printer = AppleScriptPrinter(analyzer=analyzer)
        return printer.visit(self, indent=indent)


@dataclass
class Expression(Node):
    pass


@dataclass
class Script(Node):
    # Properties are in the "<maybe binding>" sections
    properties: List[PropertyDecl] = field(default_factory=list)
    handlers: List[Handler] = field(default_factory=list)
    # Probably unneeded given that the main body is in the "on run" handler
    body: List[Statement] = field(default_factory=list)


@dataclass
class Keyword(Node):
    value: str


@dataclass
class Statement(Node):
    pass


@dataclass
class Comment(Statement):
    comment: str


@dataclass
class PropertyDecl(Statement):
    # e.g. `property foo : 42`
    name: str
    initial_value: Expression


# functions
@dataclass
class Handler(Node):
    # e.g. `on sayHello(name, greeting)`
    name: str
    parameters: List[str] = field(default_factory=list)
    body: List[Statement] = field(default_factory=list)


@dataclass
class HandlerCall(Expression):
    handler_name: str
    arguments: List[Expression]
    target: Optional[Expression] = None  # `my` or some script object


@dataclass
class SetStatement(Statement):
    # `set x to expr`
    target: LValue
    value: Expression


@dataclass
class VariableDeclaration(Statement):
    # `local x, y` or `global myVar`
    names: List[str]
    is_global: bool = False


@dataclass
class LValue(Node):
    obj: Expression


@dataclass
class IfStatement(Statement):
    condition: Expression
    else_pos: int
    then_block: List[Statement]
    end_if_pos: Optional[int] = None
    else_block: Optional[List[Statement]] = None


class RepeatKind(Enum):
    FOREVER = auto()
    WHILE = auto()
    UNTIL = auto()
    TIMES = auto()
    WITH_COUNTER = auto()  # e.g. `repeat with i from 1 to 10`
    WITH_IN = auto()  # e.g. `repeat with i in X`


@dataclass
class RepeatStatement(Statement):
    kind: RepeatKind
    end_repeat_pos: int

    # Only some fields are used depending on kind
    condition: Optional[Expression] = None
    times: Optional[Expression] = None
    counter_var: Optional[str] = None
    from_expr: Optional[Expression] = None
    to_expr: Optional[Expression] = None
    by_expr: Optional[Expression] = None
    in_expr: Optional[Exprresion] = None
    body: List[Statement] = field(default_factory=list)


@dataclass
class TryStatement(Statement):
    try_block: List[Statement]
    on_error_var: Optional[str] = None  # `on error errMsg number errNum`
    on_error_block: Optional[List[Statement]] = None
    end_try_pos: Optional[int] = None


@dataclass
class TellBlock(Statement):
    # `tell application "Finder"` ... `end tell`
    target: Expression
    body: List[Statement]
    is_done: Optional[bool] = False


@dataclass
class ReturnStatement(Statement):
    value: Optional[Expression] = None  # `return` or `return expr`


@dataclass
class ExitRepeat(Statement):
    pass


@dataclass
class ExprStatement(Statement):
    expr: Expression


@dataclass
class StringLiteral(Expression):
    value: str


@dataclass
class NumberLiteral(Expression):
    value: int  # AppleScript numbers are usually double? keep decimal?


@dataclass
class BooleanLiteral(Expression):
    value: bool


@dataclass
class DateLiteral(Expression):
    # e.g. `date "Friday, January 1, 2021 12:00:00 am"`
    text: str  # keep original text? TODO: parse datetime if needed


@dataclass
class MissingValueLiteral(Expression):
    pass


@dataclass
class VariableRef(Expression):
    name: str


@dataclass
class ListLiteral(Expression):
    # `{1, 2, "foo"}`
    elements: List[Expression]


@dataclass
class RecordField(Node):
    label: str
    value: Expression


@dataclass
class RecordLiteral(Expression):
    # `{foo: 1, bar: "hi"}`
    fields: List[RecordField]


class BinaryOpKind(Enum):
    ADD = auto()  # +
    SUB = auto()  # -
    MUL = auto()  # *
    DIV = auto()  # /
    MOD = auto()  # mod
    POW = auto()  # ^
    CONCAT = auto()  # &

    EQ = auto()  # is, =
    NE = auto()  # is not, ≠
    LT = auto()
    LE = auto()
    GT = auto()
    GE = auto()

    COERCE = auto()  # x as type
    CONTAINS = auto()

    GET_INDEXED = auto()  # X Y
    GET_PROPERTY = auto()  # X of Y
    EVERY = auto()  # every X of Y
    THRU = auto()  # X thru Y
    GENERIC_ALIAS = auto()

    AND = auto()
    OR = auto()


BINARY_OP_MAPPING = {
    "Subtract": BinaryOpKind.SUB,
    "Add": BinaryOpKind.ADD,
    "Equal": BinaryOpKind.EQ,
    "NotEqual": BinaryOpKind.NE,  # was NQ, typo
    "Concatenate": BinaryOpKind.CONCAT,
    "Remainder": BinaryOpKind.MOD,
    "Divide": BinaryOpKind.DIV,
    "Multiply": BinaryOpKind.MUL,
    "Power": BinaryOpKind.POW,
    "LessThanOrEqual": BinaryOpKind.LE,
    "LessThan": BinaryOpKind.LT,
    "GreaterThan": BinaryOpKind.GT,
    "GreaterThanOrEqual": BinaryOpKind.GE,
    "Coerce": BinaryOpKind.COERCE,
    "Contains": BinaryOpKind.CONTAINS,
    # 'And'                 : BinaryOpKind.AND,
    # 'Or'                  : BinaryOpKind.OR,
}


@dataclass
class BinaryOp(Expression):
    op: BinaryOpKind
    left: Expression
    right: Optional[Expression] = None


# Kinda messy but And/Or needs to be specially handled
# because of their short-circuit evaluation behavior
@dataclass
class AndOp(BinaryOp):
    op: BinaryOpKind = field(default=BinaryOpKind.AND, init=False)
    right_end_pos: Optional[int] = None


@dataclass
class OrOp(BinaryOp):
    op: BinaryOpKind = field(default=BinaryOpKind.OR, init=False)
    right_end_pos: Optional[int] = None


class UnaryOpKind(Enum):
    NEG = auto()  # -x
    NOT = auto()  # not x
    END_OF = auto()


UNARY_OP_MAPPING = {"Negate": UnaryOpKind.NEG, "Not": UnaryOpKind.NOT}


@dataclass
class UnaryOp(Expression):
    op: UnaryOpKind
    operand: Expression


@dataclass
class CommandCall(Expression):
    # e.g. `display dialog "Hi" buttons {"OK"} default button 1`
    command_name: str
    target: Optional[Expression] = None  # explicit "tell" target, or None for implicit
    arguments: List[str] = field(default_factory=list)


def number_to_code(num):
    num_bytes = (num.bit_length() + 7) // 8
    return num.to_bytes(num_bytes, "big").decode("ascii")


def convert_literal(lit, target=None):
    if isinstance(lit, list):
        lit = lit[1]
    if isinstance(lit, rto.Object):
        lit = lit.value
    if isinstance(lit, rto.Constant):
        return Keyword(value=number_to_code(lit.value))
    elif isinstance(lit, rto.Fixnum):
        return NumberLiteral(value=lit.value)
    elif isinstance(lit, bytes):
        return StringLiteral(value=lit.decode())
    elif isinstance(lit, rto.String):
        return StringLiteral(value=lit.value.decode("utf-16-be"))
    elif isinstance(lit, db.Descriptor):

        if lit.content[7] == 2:
            # https://mac-alias.readthedocs.io/en/latest/alias_fmt.html
            # TODO: Handle version 3?
            app_name = lit.content[51:].split(b".app")[0].decode(errors="ignore")
        else:
            app_name = lit.content.split(b".app/")[0].split(b":")[-1].decode()
        return VariableRef(name=app_name)
