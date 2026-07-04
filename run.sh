#!/usr/bin/env bash
# Run lldb_wrapper against Apple's system Python so `import lldb` resolves
# against /Library/Developer/CommandLineTools/.../LLDB.framework.
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH="$(/usr/bin/lldb -P)${PYTHONPATH:+:$PYTHONPATH}"
cd "$DIR"
exec /usr/bin/python3 -m lldb_wrapper "$@"
