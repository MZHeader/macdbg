import struct
import sys

from macdbg._vendor.osa.jinmo_applescript_disassembler.engine.util import opcodes, comments
from macdbg._vendor.osa.jinmo_applescript_disassembler.engine.fasparser import Loader

from macdbg._vendor.osa.applescript_decompiler.ast import *

# Some hardcoded offset in apple script binary
# root -> (<function index> -> (name, ..., literal, code))
ROOT_OFFSET = -1

# function object
NAME_OFFSET = 0
ARGS_OFFSET = 2
LITERAL_OFFSET = 5
CODE_OFFSET = 6


def run_decompiler(f, add_comments=False, force=False, analyzer=None, debug=False):
    # OSAStore can serialize a single handler without the enclosing script table.
    root = [None, None, f] if isinstance(f, list) and f and f[0] == 16 else f[ROOT_OFFSET]

    # assert code['kind'] == 'untypedPointerBlock'  # I think it doesn't matter
    def decompile(function_offset, add_comments=False):  # function number
        state = {"pos": 0}
        function = root[function_offset]

        print("-- === data offset %d ===" % function_offset)

        if type(function) is not list:
            print("-- <not a function>")
            return

        # In one sample, when it kinda looks like a script block?
        if function[0] == 15:
            if force:
                print(
                    f"-- {function[NAME_OFFSET + 1]} looks like a script block (?). Recursing."
                )
                return run_decompiler(function, add_comments, force)
            else:
                print(
                    f"-- {function[NAME_OFFSET + 1]} looks interesting. Try `--force`"
                )

        if len(function) < 7:
            print("-- <maybe binding?>", function)
            return

        literals = function[LITERAL_OFFSET + 1]
        name = function[NAME_OFFSET + 1]
        args = function[ARGS_OFFSET + 1]

        print("-- Function name :", name)
        print("-- Function arguments: ", end=" ")

        _args = []
        if isinstance(args, list) and len(args) >= 3 and isinstance(args[2], list):
            print(args[2][1:])
            _args = args[2][1:]
        else:
            print("-- <empty or unknown>")

        handler = Handler(
            name=name.decode() if isinstance(name, bytes) else name,
            parameters=[e.decode() if isinstance(e, bytes) else str(e) for e in _args],
            body=[],
        )

        code = bytearray(function[CODE_OFFSET + 1].value)

        def word():
            r = struct.unpack(">H", code[state["pos"] : state["pos"] + 2])[0]
            state["pos"] += 2
            return r - 0x10000 if r & 0x8000 else r

        def literal(x):
            if x >= len(literals):
                return "[L%d]" % x
            return literals[x]

        def variable(x, local=False):
            if local and len(_args) > x:
                _x = _args[x]
                return "[var_%d (%r)]" % (
                    x,
                    _x.decode() if isinstance(_x, bytes) else str(_x),
                )
            return "[var_%d]" % x

        # Runtime stack
        _stack = []

        # Stack that keeps track of the current block we are writing on.
        # Maintain as stack to represent things that are "block-ish" like
        # handlers, if/else, try, repeat, etc
        block_stack = [handler]

        _var = None
        _prev_op = None

        while state["pos"] < len(code):
            _curr_pos = state["pos"]
            _comment = " " + "%05x" % state["pos"] + " "
            c = code[state["pos"]]
            state["pos"] += 1
            op = opcodes[c]

            _comment += op + " "
            _statements = []

            if debug:
                print(_stack)
                print(_comment, end = ' ')

            # AndOp/OrOp special cases since they have some control flow
            # but are actuall expressions
            if _stack and (
                isinstance(block_stack[-1], AndOp) or isinstance(block_stack[-1], OrOp)
            ):
                if _curr_pos == block_stack[-1].right_end_pos:
                    block_stack[-1].right = _stack.pop()
                    _op = block_stack.pop()
                    _stack.append(BinaryOp(op=_op.op, left=_op.left, right=_op.right))

            if op == "Jump":
                _address = _curr_pos + 1 + word()
                _comment += hex(_address) + " "
                # Assume repeat blocks follow proper jump
                # Use Jump address to infer `else` block for `if-then-else`
                curr_index = len(block_stack) - 1
                while curr_index > 0 and (
                    not isinstance(block_stack[curr_index], IfStatement)
                    or block_stack[curr_index].end_if_pos is not None
                ):
                    curr_index -= 1
                _block = block_stack[curr_index]

                if isinstance(_block, IfStatement):
                    _block.end_if_pos = _address
                    if _stack:
                        if _var is not None:
                            _statements.append(
                                SetStatement(
                                    # TODO: handle generic values
                                    target=LValue(obj=_var),
                                    value=_stack.pop(),
                                )
                            )
                            _var = None
                        else:
                            _statements.append(ExprStatement(expr=_stack.pop()))
            elif op in ["PushLiteral", "PushLiteralExtended"]:
                v = word() if "Extended" in op else (c & 0xF)
                _comment += (
                    str(v)
                    + " # "
                    + str(convert_literal(literal(v)))
                    + " "
                    + str(literal(v))
                )
                _lit = convert_literal(literal(v))
                _stack.append(_lit)
            elif op in ["Push0", "Push1", "Push2", "Push3"]:
                _stack.append(NumberLiteral(value=int(op[-1])))
            elif op == "PushMinus1":
                _stack.append(NumberLiteral(value=int(-1)))
            elif op in ["PushTrue", "PushFalse"]:
                _stack.append(BooleanLiteral(value=op == "PushTrue"))
            elif op in ["PushIt", "PushMe", "PushUndefined"]:
                if "Me" in op:
                    _stack.append(VariableRef("my"))
                elif "It" in op:
                    _stack.append(VariableRef("__it__"))
            elif op in ["PushVariable", "PushVariableExtended"]:
                v = variable(
                    word() if "Extended" in op else (c & 0xF), "Extended" not in op
                )
                _comment += v + " "
                _stack.append(VariableRef(v))
            elif op in ["PushGlobal", "PushGlobalExtended"]:
                v = literal(word() if "Extended" in op else (c & 0xF))
                if isinstance(v, bytes):
                    _stack.append(VariableRef(name=v.decode()))
                else:
                    _stack.append(convert_literal(v))
                _comment += str(v) + " "
            elif op in ["PopGlobal", "PopGlobalExtended"]:
                v = word() if "Extended" in op else (c & 0xF)
                _comment += str(literal(v))
                _var = VariableRef(literal(v).decode())
            elif op in ["PopVariable", "PopVariableExtended"]:
                v = variable(word() if "Extended" in op else (c & 0xF))
                _comment += str(v) + " "
                _var = VariableRef(v)
            elif op == "Dup" and _stack:
                curr_index = len(block_stack) - 1
                # Find enclosing `RepeatStatement`
                while curr_index > 0 and not isinstance(
                    block_stack[curr_index], RepeatStatement
                ):
                    curr_index -= 1

                _block = block_stack[curr_index]
                # Repeat blocks have a random Dup in them Not really sure what
                # they are for. We can just ignore them?
                if (
                    isinstance(_block, RepeatStatement)
                    and _block.kind != RepeatKind.FOREVER
                ):
                    pass
                else:
                    _stack.append(_stack[-1])
            elif op in BINARY_OP_MAPPING:
                r = _stack.pop()
                l = _stack.pop()
                _stack.append(BinaryOp(op=BINARY_OP_MAPPING[op], left=l, right=r))
            elif op in UNARY_OP_MAPPING:
                exp = _stack.pop()
                _stack.append(UnaryOp(op=UNARY_OP_MAPPING[op], operand=exp))
            elif op == "Exit":
                # Maybe check current block is repeat?
                # Should only be during repeat
                _statements.append(ExitRepeat())
            elif op == "Tell":
                _comment += str(word()) + " "
                _target = _stack.pop()
                block_stack.append(TellBlock(target=_target, body=[]))
            elif op == "EndTell":
                # Look for the containing TellBlock
                curr_index = -1
                while not isinstance(block_stack[curr_index], TellBlock):
                    curr_index -= 1

                block_stack[curr_index].is_done = True

                if _stack and not (
                    isinstance(block_stack[curr_index].target, Keyword)
                    and block_stack[curr_index].target.value == "misccura"
                ):
                    _curr = _stack.pop()
                    if _var is not None:
                        _statements.append(
                            SetStatement(
                                # TODO: handle generic values
                                target=LValue(obj=_var),
                                value=_curr,
                            )
                        )
                        _var = None
                    else:
                        _statements.append(ExprStatement(expr=_curr))

            elif op in ("MakeObjectAlias", "MakeComp"):
                t = c - 23
                sub_operation = comments.get(t, "<Unknown>")
                _comment += sub_operation
                if sub_operation == "GetPositionEnd":
                    operand = _stack.pop()
                    _stack.append(UnaryOp(op=UnaryOpKind.END_OF, operand=operand))
                elif sub_operation == "GetProperty":
                    l = _stack.pop()
                    r = _stack.pop()
                    _stack.append(
                        BinaryOp(op=BinaryOpKind.GET_PROPERTY, left=l, right=r)
                    )
                elif sub_operation == "GetEvery":
                    r = _stack.pop()
                    l = _stack.pop()
                    _stack.append(BinaryOp(op=BinaryOpKind.EVERY, left=l, right=r))
                elif "GetIndexed" in sub_operation:
                    # Treat GetIndexed similar to GetProperty?
                    # content X of Y
                    # I'm not really sure if this is correct

                    l = _stack.pop()
                    r = _stack.pop()

                    target = _stack.pop()

                    l = BinaryOp(op=BinaryOpKind.GET_INDEXED, left=r, right=l)
                    _stack.append(
                        BinaryOp(op=BinaryOpKind.GET_PROPERTY, left=l, right=target)
                    )
                elif "GetKeyFrom" in sub_operation:
                    # Also not sure if this is correct
                    l = _stack.pop()
                    r = _stack.pop()
                    if l.value == "kfrmID  ":
                        _type = _stack.pop()
                        _stack.pop()
                        l.value += _type.value
                    _stack.append(
                        BinaryOp(op=BinaryOpKind.GET_PROPERTY, left=l, right=r)
                    )
                elif "GetRange" in sub_operation:
                    _comment += str(_stack)
                    _to = _stack.pop()
                    _from = _stack.pop()
                    _prop = _stack.pop()
                    _stack.pop()
                    _var = _stack.pop()
                    _stack.pop()
                    _range = BinaryOp(op=BinaryOpKind.THRU, left=_from, right=_to)

                    _range_of = BinaryOp(
                        op=BinaryOpKind.GET_PROPERTY, left=_range, right=_var
                    )
                    _stack.append(
                        BinaryOp(
                            op=BinaryOpKind.GET_PROPERTY, left=_prop, right=_range_of
                        )
                    )
                else:
                    print(f"-- Warning {op}:{sub_operation} is not implemented")
                    _comment += " (not implemented)"
                    _stack.pop()
            elif op == "SetData":
                _var = _stack.pop()
            elif op == "GetData":
                pass
            elif op in ["And", "Or"]:
                _next = _curr_pos + 1 + word()
                _comment += hex(_next) + " "
                _left = _stack.pop()

                if op == "And":
                    block_stack.append(AndOp(left=_left, right_end_pos=_next))
                else:
                    block_stack.append(OrOp(left=_left, right_end_pos=_next))

            elif op == "TestIf":
                _else_pos = _curr_pos + 1 + word()
                _comment += hex(_else_pos)
                _cond = _stack.pop()
                _block = IfStatement(
                    condition=_cond, else_pos=_else_pos, then_block=[], else_block=[]
                )
                block_stack.append(_block)
            elif op == "MessageSend":
                v = word()
                event_code = number_to_code(
                    literal(v).value.identifier[0]
                ) + number_to_code(literal(v).value.identifier[1])
                _comment += str(v) + " (" + event_code  + ") # " + str(literal(v))


                args_count = _stack.pop().value
                if args_count == 0:
                    args = []
                else:
                    args = _stack[-args_count:]
                    _stack = _stack[:-args_count]

                _stack.append(
                    CommandCall(
                        command_name=event_code, arguments=[_stack.pop()] + args
                    )
                )
            elif op == "PositionalMessageSend":
                v = word()
                _comment += str(v) + " # " + str(literal(v))
                args_count = _stack.pop().value

                if args_count == 0:
                    args = []
                else:
                    args = _stack[-args_count:]
                    _stack = _stack[:-args_count]

                if _stack:
                    _target = _stack.pop()
                    if _target.name == "__it__":
                        _target = None
                else:
                    _target = None

                _stack.append(
                    HandlerCall(
                        handler_name=literal(v).decode(), arguments=args, target=_target
                    )
                )
            elif op == "StoreResult" and _stack:
                _curr = _stack.pop()
                if _var is not None:
                    _statements.append(
                        SetStatement(
                            # TODO: handle generic values
                            target=LValue(obj=_var),
                            value=_curr,
                        )
                    )
                    _var = None
                else:
                    _statements.append(ExprStatement(expr=_curr))
            elif op == "LinkRepeat":
                v = word() + _curr_pos + 1
                _comment += hex(v) + " "
                block_stack.append(
                    RepeatStatement(
                        kind=RepeatKind.FOREVER, end_repeat_pos=v  # By default
                    )
                )
            elif op == "RepeatNTimes":
                _stack.pop()  # remove PushOne
                N = _stack.pop()
                _comment += str(N)
                _block = block_stack[-1]
                _block.kind = RepeatKind.TIMES
                _block.times = N
            elif op == "RepeatWhile":
                cond = _stack.pop()
                _block = block_stack[-1]
                _block.kind = RepeatKind.WHILE
                _block.condition = cond
            elif op == "RepeatUntil":
                cond = _stack.pop()
                _block = block_stack[-1]
                _block.kind = RepeatKind.UNTIL
                _block.condition = cond
            elif op == "RepeatInCollection":
                v = variable(word())
                _comment += v
                _stack.pop()  # Push1
                _stack.pop()  # Result of len(_arr)
                _arr = _stack.pop()
                _block = block_stack[-1]
                _block.kind = RepeatKind.WITH_IN
                _block.counter_var = VariableRef(v)
                _block.in_expr = _arr
            elif op == "RepeatInRange":
                v = variable(word())
                _comment += v

                _by = _stack.pop()
                _to = _stack.pop()
                _from = _stack.pop()

                _block = block_stack[-1]
                _block.kind = RepeatKind.WITH_COUNTER
                _block.from_expr = _from
                _block.to_expr = _to
                _block.by_expr = _by
                _block.counter_var = VariableRef(v)
            elif op == "Return":
                # TODO Make Return Robust
                if _stack and (
                    isinstance(_stack[-1], CommandCall)
                    or isinstance(_stack[-1], HandlerCall)
                ):
                    _statements.append(ExprStatement(expr=_stack.pop()))
                elif _stack:
                    _statements.append(ReturnStatement(value=_stack.pop()))
                elif op != _prev_op:
                    _statements.append(ReturnStatement())

            elif op == "MakeVector":
                vector_length = _stack.pop().value
                if vector_length == 0:
                    _list = ListLiteral(elements=[])
                else:
                    _list = ListLiteral(elements=_stack[-vector_length:])
                    _stack = _stack[:-vector_length]
                _stack.append(_list)
            elif op == "MakeRecord":
                record_length = _stack.pop().value
                if record_length == 0:
                    _rec = RecordLiteral(fields=[])
                else:
                    vals = _stack[-record_length:]
                    result = [
                        RecordField(label=vals[i], value=vals[i + 1])
                        for i in range(0, len(vals), 2)
                    ]
                    _rec = RecordLiteral(fields=result)
                _stack = _stack[:-record_length]
                _stack.append(_rec)
                pass
            elif op == "ErrorHandler":
                _comment += " " + hex(_curr_pos + 1 + word())
                block_stack.append(TryStatement(try_block=[], on_error_block=[]))
            elif op == "EndErrorHandler":
                v = _curr_pos + 1 + word()
                _comment += " " + hex(v)

                curr_index = len(block_stack) - 1
                while curr_index > 0 and not isinstance(
                    block_stack[curr_index], TryStatement
                ):
                    curr_index -= 1

                if _stack and _var is not None:
                    _statements.append(
                        SetStatement(
                            # TODO: handle generic values
                            target=LValue(obj=_var),
                            value=_stack.pop(),
                        )
                    )
                    _var = None
                elif _stack and (
                    isinstance(_stack[-1], CommandCall)
                    or isinstance(_stack[-1], HandlerCall)
                ):
                    _statements.append(ExprStatement(expr=_stack.pop()))

                block_stack[curr_index].try_block.extend(_statements)
                _statements = []

                block_stack[curr_index].end_try_pos = v
            elif op == "HandleError":
                _comment += " " + variable(word()) + " " + variable(word())
            elif op == "PushParentVariable":
                v = "[parent]" + variable(word())
                _comment += " " + str(word()) + " " + v + " "
                _stack.append(VariableRef(v))
            elif op == "PopParentVariable":
                v = "[parent]" + variable(word())
                _comment += " " + str(word()) + " " + v + " "
                _var = VariableRef(v)
            elif op == "Error":
                args_count = _stack.pop()
                if not isinstance(args_count, NumberLiteral):
                    args_count = _stack.pop().value
                    _s = args_count
                else:
                    _s = None
                    args_count = args_count.value

                if args_count == 0:
                    args = []
                else:
                    args = _stack[-args_count:]
                    _stack = _stack[:-args_count]

                if _s is not None:
                    args = [_s] + args
                _stack.pop()
                _statements.append(CommandCall(command_name="error", arguments=args))

            # elif op == 'Quotient':
            #     pass
            # elif op == 'GetResult':
            #     pass
            # elif op == 'StartsWith':
            #     pass
            # elif op == 'EndsWith':
            #     pass
            # elif op == 'Pop':
            #     pass
            # elif op == 'DefineActor':
            #     print(hex(word()), end=' ')
            # elif op == 'EndDefineActor':
            #     pass
            else:
                _comment += "<disassembler not implemented> " + op

            _block = block_stack[-1]

            if _comment is not None and add_comments:
                _statements = [Comment(comment=_comment)] + _statements

            if debug: print(' '.join(_comment.split(' ')[2:]))

            _prev_op = op
            while True:
                while True:
                    _curr_index = -1
                    while isinstance(block_stack[_curr_index], AndOp) or isinstance(
                        block_stack[_curr_index], OrOp
                    ):
                        _curr_index -= 1

                    _block = block_stack[_curr_index]
                    if isinstance(_block, TellBlock):
                        if _statements:
                            _block.body.extend(_statements)
                            _statements = []
                        # If we have encountered an end tell
                        if _block.is_done:
                            # Special case to handle (ASCII character X) & (ASCII character X) ... etc
                            # For some reason, this is handled internally as a tell/endtellx
                            if not (
                                isinstance(_block.target, Keyword)
                                and _block.target.value == "misccura"
                            ):
                                _statements.append(_block)
                            block_stack.pop()
                            continue
                    elif isinstance(_block, TryStatement):
                        if _statements:
                            if _block.end_try_pos is not None:
                                _block.on_error_block.extend(_statements)
                            else:
                                _block.try_block.extend(_statements)
                            _statements = []
                        # If we've reached the end address of the try block
                        if (
                            _block.end_try_pos is not None
                            and _curr_pos >= _block.end_try_pos
                        ):
                            _statements.append(block_stack.pop())
                            continue
                    elif isinstance(_block, RepeatStatement):
                        if _statements and (_curr_pos <= _block.end_repeat_pos):
                            _block.body.extend(_statements)
                            _statements = []
                        # If we've reached the end address of the repeat block
                        if (
                            _block.end_repeat_pos is not None
                            and _curr_pos >= _block.end_repeat_pos
                        ):
                            _statements.append(block_stack.pop())
                            continue
                    elif isinstance(_block, IfStatement):
                        # We need to keep track the end of the if block, from address in TestIf
                        # and the end of the else block, from the address in Jump
                        if _statements and (_curr_pos < _block.else_pos):
                            _block.then_block.extend(_statements)
                            _statements = []
                        elif _block.end_if_pos is not None:
                            if _statements and (_curr_pos <= _block.end_if_pos):
                                _block.else_block.extend(_statements)
                                _statements = []
                            if _curr_pos == _block.end_if_pos and _stack:
                                _block.else_block.append(_stack.pop())
                            if _curr_pos == _block.end_if_pos:
                                _statements.append(block_stack.pop())
                                continue
                    elif isinstance(_block, Handler):
                        if _statements:
                            _block.body.extend(_statements)

                    break

                # If we are at the end of the decompilation, we should
                # attach all handlers back to the root handler
                if state["pos"] >= len(code) and len(block_stack) > 1:
                    _statements.append(block_stack.pop())
                else:
                    break

            # if _comment is not None and add_comments:
            #     block_stack[0].body.append(Comment(comment=_comment))

        return block_stack[0]

    handlers = []
    for cur_function_offset in range(2, len(root)):
        try:
            ret = decompile(cur_function_offset, add_comments=add_comments)
            if ret is not None:
                handlers.append(ret)
        except Exception as e:
            print("-- Failed to decompile")
            if not force:
                raise e
    return Script(handlers=handlers).to_source(analyzer=analyzer)
