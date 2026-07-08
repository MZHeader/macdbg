// macdbg.app bundle executable — a tiny NATIVE launcher.
//
// Why this exists: macOS/LaunchServices launches a *script*-based .app bundle
// under Rosetta (x86_64) by default on Apple Silicon. macdbg is arm64-only, so a
// shell-script launcher makes a Finder double-click demand Rosetta (and fail
// with LaunchServices error -10669 when it isn't installed) even though nothing
// here is x86_64. A native arm64 Mach-O is launched arm64 directly, so no user
// is ever asked for Rosetta.
//
// It resolves the repo from its own path (…/macdbg.app/Contents/MacOS/macdbg →
// four components up = repo root), then execs GUI/run.sh with our arguments,
// after pointing stdout/stderr at ~/.macdbg/launch.log for post-mortem — the
// same behaviour the old shell launcher had. run.sh does the real work
// (arch/SDK setup, interpreter selection, native window vs browser fallback).

#include <mach-o/dyld.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    char exe[PATH_MAX];
    uint32_t sz = sizeof(exe);
    if (_NSGetExecutablePath(exe, &sz) != 0)
        return 1;
    char repo[PATH_MAX];
    if (!realpath(exe, repo))
        return 1;

    // repo = …/macdbg.app/Contents/MacOS/macdbg → strip 4 trailing components
    // (macdbg, MacOS, Contents, macdbg.app) to land on the repo root.
    for (int i = 0; i < 4; i++) {
        char *slash = strrchr(repo, '/');
        if (!slash)
            return 1;
        *slash = '\0';
    }
    char script[PATH_MAX];
    if (snprintf(script, sizeof(script), "%s/GUI/run.sh", repo) >= (int)sizeof(script))
        return 1;

    // Append this launch's output to ~/.macdbg/launch.log so a failed launch
    // leaves a trace, mirroring the old shell launcher.
    const char *home = getenv("HOME");
    if (home) {
        char dir[PATH_MAX], log[PATH_MAX];
        snprintf(dir, sizeof(dir), "%s/.macdbg", home);
        mkdir(dir, 0755);
        snprintf(log, sizeof(log), "%s/.macdbg/launch.log", home);
        if (freopen(log, "a", stdout) && freopen(log, "a", stderr)) {
            time_t t = time(NULL);
            char ts[64];
            strftime(ts, sizeof(ts), "%F %T", localtime(&t));
            fprintf(stderr, "=== launch %s (native arm64) ===\n", ts);
            fflush(stderr);
        }
    }

    // exec run.sh, passing our arguments through. execv keeps the current
    // environment (so MACDBG_SELFTEST etc. survive) and the redirected fds.
    char **child = calloc(argc + 1, sizeof(char *));
    if (!child)
        return 1;
    child[0] = script;
    for (int i = 1; i < argc; i++)
        child[i] = argv[i];
    execv(script, child);
    perror("macdbg: could not exec GUI/run.sh");
    return 127;
}
