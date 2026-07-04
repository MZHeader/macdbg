#!/usr/bin/env bash
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
VENDOR="$DIR/vendor"

if [ ! -d "$VENDOR/textual" ]; then
    echo "error: $VENDOR/textual is missing." >&2
    echo "Fetch it once with:  /usr/bin/python3 -m pip install --target vendor 'textual>=8,<9'" >&2
    exit 1
fi

export PYTHONPATH="$(/usr/bin/lldb -P):$DIR:$VENDOR${PYTHONPATH:+:$PYTHONPATH}"
cd "$DIR"
exec /usr/bin/python3 -m lldb_wrapper "$@"
