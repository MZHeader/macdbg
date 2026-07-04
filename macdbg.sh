#!/usr/bin/env bash
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
VENDOR="$DIR/vendor"

# The UI dependencies (textual, rich, ...) are vendored under vendor/ and ship
# with the repo, so this should only fire on a partial/broken checkout.
if [ ! -d "$VENDOR/textual" ]; then
    echo "error: $VENDOR/textual is missing — vendored dependencies ship with the repo." >&2
    echo "Re-clone the full repository:  git clone https://github.com/MZHeader/macdbg" >&2
    exit 1
fi

# lldb -P prints the path to the system LLDB Python bindings, which are not
# available from PyPI; DIR puts the macdbg package on the path; VENDOR supplies
# the UI dependencies. This wiring is why macdbg is launched via this script.
export PYTHONPATH="$(/usr/bin/lldb -P):$DIR:$VENDOR${PYTHONPATH:+:$PYTHONPATH}"
cd "$DIR"
exec /usr/bin/python3 -m macdbg "$@"
