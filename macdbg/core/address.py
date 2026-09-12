"""Resolve navigation addresses without evaluating code in the target."""
import re


def resolve(debugger, expression):
    text = str(expression).strip()
    if not text:
        raise ValueError("Enter an address, symbol, or register.")
    offset = 0
    suffix = re.search(r"\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)$", text)
    if suffix and suffix.start() > 0:
        offset = int(suffix[2], 0) * (-1 if suffix[1] == "-" else 1)
        text = text[:suffix.start()].strip()
    try:
        address = int(text, 0)
        candidates = [(address, text)]
    except ValueError:
        frame = debugger.frame()
        reg = frame.FindRegister(text.lstrip("$")) if frame else None
        if reg and reg.IsValid():
            candidates = [(reg.GetValueAsUnsigned(), text)]
        else:
            target = debugger.target
            if not target or not target.IsValid():
                raise ValueError("No target loaded.")
            module_name, separator, name = text.partition("!")
            if not separator:
                name, module_name = text, ""
            candidates = []
            for contexts in (target.FindFunctions(name), target.FindSymbols(name)):
                for index in range(contexts.GetSize()):
                    context = contexts.GetContextAtIndex(index)
                    module = context.GetModule().GetFileSpec().GetFilename() or ""
                    if module_name and module != module_name:
                        continue
                    function = context.GetFunction()
                    symbol = context.GetSymbol()
                    item = function if function.IsValid() else symbol
                    if not item.IsValid():
                        continue
                    address = item.GetStartAddress().GetLoadAddress(target)
                    if address != (1 << 64) - 1:
                        candidates.append((address, "{}!{}".format(module, item.GetName() or name)))
    result = {}
    for address, label in candidates:
        address += offset
        if not 0 <= address < (1 << 64):
            raise ValueError("Address is outside the 64-bit address space.")
        result.setdefault(address, {"addr": hex(address), "label": label})
    if not result:
        raise ValueError("No match. Use a symbol, $register, or address with an optional +/- offset.")
    return list(result.values())
