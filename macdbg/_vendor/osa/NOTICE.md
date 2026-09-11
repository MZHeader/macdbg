# AppleScript static decompiler

Vendored from https://github.com/pberba/applescript-decompiler at commit
`8ffcaa5dc07d4ece757a459cbdda85aba3dc4bd8` (MIT; see LICENSE).
The included parser derives from https://github.com/Jinmo/applescript-disassembler.

Local changes: package-qualified imports, removal of the CLI and optional analyzer
loading, file-like parser input, standalone handler roots, and returning reconstructed text separately from
diagnostics. The worker runs the parser without invoking an AppleScript engine.

Reconstruction is approximate: names, properties, terminology and control flow
may be incomplete. The captured byte stream remains the authoritative artifact.
