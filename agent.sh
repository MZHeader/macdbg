#!/usr/bin/env bash
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"

# lldb -P prints the path to the system LLDB Python bindings, which are not
# available from PyPI; DIR puts the macdbg package on the path. Unlike
# macdbg.sh, this headless agent never imports the vendored Textual UI, so
# vendor/ is not required on PYTHONPATH.
export PYTHONPATH="$(/usr/bin/lldb -P):$DIR${PYTHONPATH:+:$PYTHONPATH}"
cd "$DIR"
exec /usr/bin/python3 -m macdbg.agent "$@"
