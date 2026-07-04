#!/usr/bin/env bash
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
VENDOR="$DIR/vendor"

export PYTHONPATH="$(/usr/bin/lldb -P):$DIR:$VENDOR${PYTHONPATH:+:$PYTHONPATH}"

if ! /usr/bin/python3 -c "import textual" 2>/dev/null; then
    echo "First-run setup: fetching textual into ./vendor..."
    /usr/bin/python3 -m pip install --quiet --target "$VENDOR" 'textual>=8,<9'
fi

cd "$DIR"
exec /usr/bin/python3 -m lldb_wrapper "$@"
