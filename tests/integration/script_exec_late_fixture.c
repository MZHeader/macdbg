#include <Carbon/Carbon.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#define LOAD(name) __typeof__(&name) call_##name = dlsym(library, #name); if (!call_##name) return 2

int main(void) {
    void *library = dlopen("/System/Library/Frameworks/Carbon.framework/Carbon", RTLD_NOW | RTLD_LOCAL);
    if (!library) return 2;
    LOAD(OpenDefaultComponent); LOAD(AECreateDesc); LOAD(OSACompile);
    LOAD(OSAExecute); LOAD(OSADispose); LOAD(AEDisposeDesc); LOAD(CloseComponent);
    ComponentInstance component = call_OpenDefaultComponent(kOSAComponentType, kOSAGenericScriptingComponentSubtype);
    AEDesc source = {typeNull, NULL};
    OSAID compiled = 0, result = 0;
    const char text[] = "return 42";
    OSAError error = call_AECreateDesc(typeUTF8Text, text, strlen(text), &source);
    if (!error) error = call_OSACompile(component, &source, 0, &compiled);
    if (error) return 3;
    error = call_OSAExecute(component, compiled, 0, kOSAModeNeverInteract, &result);
    printf("OSA-LATE:rc=%d\n", (int)error);
    call_OSADispose(component, compiled); call_AEDisposeDesc(&source); call_CloseComponent(component);
    return error == userCanceledErr ? 0 : 1;
}
