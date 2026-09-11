#include <Carbon/Carbon.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((constructor)) static void early_descriptor(void) {
    if (getenv("MACDBG_TEST_EARLY_DESC")) {
        AEDesc descriptor = {typeNull, NULL};
        AECreateDesc(typeUTF8Text, "return 0", 8, &descriptor);
        AEDisposeDesc(&descriptor);
    }
}

__attribute__((noinline)) static OSAError run_execute(ComponentInstance component,
                                                     OSAID script, OSAID *result) {
    return OSAExecute(component, script, kOSANullScript, kOSAModeNeverInteract, result);
}

int main(int argc, char **argv) {
    if (argc != 4 || strchr(argv[2], '"')) return 64;
    const char *mode = argv[1], *path = argv[2], *expected = argv[3];
    char source[4096];
    snprintf(source, sizeof(source),
        "set f to open for access POSIX file \"%s\" with write permission\n"
        "write \"executed\" to f\nclose access f\nreturn 42", path);
    char oracle[4096];
    snprintf(oracle, sizeof(oracle), "%s.source.txt", path);
    FILE *source_file = fopen(oracle, "wb");
    if (!source_file || fwrite(source, 1, strlen(source), source_file) != strlen(source)) return 7;
    fclose(source_file);
    ComponentInstance component = OpenDefaultComponent(kOSAComponentType,
                                                       kOSAGenericScriptingComponentSubtype);
    if (!component) return 2;
    AEDesc text = {typeNull, NULL}, stored = {typeNull, NULL};
    AEDesc event = {typeNull, NULL}, target = {typeNull, NULL};
    OSAID compiled = kOSANullScript;
    OSAError error;
    if (!strcmp(mode, "replace")) {
        error = AECreateDesc(typeUTF8Text, "return 0", 8, &text);
        if (!error) error = AEReplaceDescData(typeUTF8Text, source, strlen(source), &text);
    } else {
        error = AECreateDesc(typeUTF8Text, source, strlen(source), &text);
    }
    if (!error && !strcmp(mode, "duplicate")) {
        AEDesc copy = {typeNull, NULL};
        error = AEDuplicateDesc(&text, &copy);
        AEDisposeDesc(&text);
        text = copy;
    }
    if (!error) error = OSACompile(component, &text, kOSAModeNull, &compiled);
    if (!error) error = OSAStore(component, compiled, typeOSAGenericStorage, kOSAModeNull, &stored);
    if (error) { printf("SETUP:%d\n", (int)error); return 3; }
    Size byte_count = AEGetDescDataSize(&stored);
    void *serialized = malloc(byte_count);
    if (!serialized || AEGetDescData(&stored, serialized, byte_count)) return 8;
    snprintf(oracle, sizeof(oracle), "%s.expected.scpt", path);
    FILE *compiled_file = fopen(oracle, "wb");
    if (!compiled_file || fwrite(serialized, 1, byte_count, compiled_file) != (size_t)byte_count) return 9;
    fclose(compiled_file);
    AEDisposeDesc(&stored);
    if (AECreateDesc(typeOSAGenericStorage, serialized, byte_count, &stored)) return 10;
    free(serialized);
    OSAID extra = 0;
    if (!strcmp(mode, "multiple")) {
        AEDesc decoy = {typeNull, NULL};
        AECreateDesc(typeUTF8Text, "return 99", 9, &decoy);
        if (OSACompile(component, &decoy, 0, &extra)) return 11;
        AEDisposeDesc(&decoy);
    }
    struct { OSAID value; unsigned char guard[8]; } result = {0x11223344, {0}};
    struct { AEDesc value; unsigned char guard[8]; } desc = {{typeNull, NULL}, {0}};
    memset(result.guard, 0xa5, sizeof(result.guard));
    memset(desc.guard, 0xa5, sizeof(desc.guard));
    int descriptor_result = 0;
    if (!strcmp(mode, "execute") || !strcmp(mode, "replace") ||
        !strcmp(mode, "duplicate") || !strcmp(mode, "multiple")) {
        error = run_execute(component, compiled, &result.value);
    } else if (!strcmp(mode, "loaded")) {
        if (OSALoad(component, &stored, 0, &extra)) return 12;
        AEDisposeDesc(&stored);
        error = run_execute(component, extra, &result.value);
    } else if (!strcmp(mode, "compile")) {
        error = OSACompileExecute(component, &text, 0, kOSAModeNeverInteract, &result.value);
    } else if (!strcmp(mode, "load")) {
        error = OSALoadExecute(component, &stored, 0, kOSAModeNeverInteract, &result.value);
    } else if (!strcmp(mode, "do")) {
        descriptor_result = 1;
        error = OSADoScript(component, &text, 0, typeSInt32, kOSAModeNeverInteract, &desc.value);
    } else if (!strcmp(mode, "event") || !strcmp(mode, "doevent")) {
        pid_t pid = getpid();
        AECreateDesc(typeKernelProcessID, &pid, sizeof(pid), &target);
        AECreateAppleEvent(kCoreEventClass, kAEOpenApplication, &target,
                          kAutoGenerateReturnID, kAnyTransactionID, &event);
        if (!strcmp(mode, "event"))
            error = OSAExecuteEvent(component, &event, compiled, kOSAModeNeverInteract, &result.value);
        else {
            descriptor_result = 1;
            error = OSADoEvent(component, &event, compiled, kOSAModeNeverInteract, &desc.value);
        }
    } else if (!strcmp(mode, "file")) {
        char file[4096];
        snprintf(file, sizeof(file), "%s.scpt", path);
        Size size = AEGetDescDataSize(&stored);
        void *data = malloc(size);
        if (!data || AEGetDescData(&stored, data, size)) return 4;
        FILE *out = fopen(file, "wb");
        if (!out || fwrite(data, 1, size, out) != (size_t)size) return 5;
        fclose(out); free(data);
        FSRef ref;
        if (FSPathMakeRef((const UInt8 *)file, &ref, NULL)) return 6;
        descriptor_result = 1;
        error = OSADoScriptFile(component, &ref, 0, typeSInt32, kOSAModeNeverInteract, &desc.value);
    } else return 65;
    int guard_ok = 1;
    for (int i = 0; i < 8; ++i)
        guard_ok &= result.guard[i] == 0xa5 && desc.guard[i] == 0xa5;
    int marker = access(path, F_OK) == 0;
    int ok = guard_ok;
    if (!strcmp(expected, "block"))
        ok &= error == userCanceledErr && !marker && result.value == 0x11223344;
    else if (!strcmp(expected, "fake"))
        ok &= !error && !marker && (descriptor_result
            ? desc.value.descriptorType == typeNull && !desc.value.dataHandle
            : result.value == kOSANullScript);
    else
        ok &= !error && marker;
    printf("OSA-GATE:%s api=%s rc=%d marker=%d guard=%d desc_size=%zu\n",
           ok ? "clean" : "FAILED", mode, (int)error, marker, guard_ok, sizeof(AEDesc));
    if (!error && strcmp(expected, "fake")) {
        if (descriptor_result) AEDisposeDesc(&desc.value);
        else OSADispose(component, result.value);
    }
    AEDisposeDesc(&target); AEDisposeDesc(&event);
    AEDisposeDesc(&stored); AEDisposeDesc(&text);
    OSADispose(component, compiled); CloseComponent(component);
    return ok ? 0 : 1;
}
