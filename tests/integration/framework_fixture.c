#include <Carbon/Carbon.h>
#include <IOKit/IOKitLib.h>
#include <dlfcn.h>
#include <objc/message.h>
#include <objc/runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int register_application(void) {
    ProcessSerialNumber psn = {0, kCurrentProcess};
    OSStatus registration = TransformProcessType(&psn, kProcessTransformToUIElementApplication);
    void *appkit = dlopen("/System/Library/Frameworks/AppKit.framework/AppKit", RTLD_NOW | RTLD_LOCAL);
    if (!appkit) return 6;
    id application = ((id (*)(id, SEL))objc_msgSend)((id)objc_getClass("NSApplication"),
                                                   sel_registerName("sharedApplication"));
    ((void (*)(id, SEL, long))objc_msgSend)(application,
                                           sel_registerName("setActivationPolicy:"), 1);
    printf("APPLICATION:registration=%d\n", (int)registration);
    return 0;
}

int main(int argc, char **argv) {
    void *image = NULL;
    if (argc > 2) {
        image = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
        if (!image) return 2;
    }
    if (argc > 1 && !strcmp(argv[1], "images")) {
        CFArrayRef bundles = CFBundleGetAllBundles();
        printf("BUNDLES:%ld\n", bundles ? CFArrayGetCount(bundles) : -1L);
        return bundles ? 0 : 3;
    }
    if (argc > 1 && !strncmp(argv[1], "application", 11)) {
        if (register_application()) return 6;
    }
    const char source[] = "return 6 * 7";
    ComponentInstance component = OpenDefaultComponent(kOSAComponentType,
                                                        kOSAGenericScriptingComponentSubtype);
    if (!component) return 4;
    AEDesc text = {typeNull, NULL}, stored = {typeNull, NULL};
    AEDesc value = {typeNull, NULL};
    OSAID compiled = kOSANullScript, loaded = kOSANullScript;
    OSAID result = kOSANullScript;
    OSStatus error = 0;
    int cold = argc > 3;
    if (cold) {
        FILE *file = fopen(argv[3], "rb");
        if (!file) return 7;
        unsigned char data[4096];
        size_t size = fread(data, 1, sizeof(data), file);
        int valid = size > 0 && size < sizeof(data) && !ferror(file);
        fclose(file);
        if (!valid) return 8;
        error = AECreateDesc(typeOSAGenericStorage, data, size, &stored);
    } else {
        error = AECreateDesc(typeUTF8Text, source, strlen(source), &text);
        if (!error) error = OSACompile(component, &text, kOSAModeNull, &compiled);
        if (!error) error = OSAStore(component, compiled, typeOSAGenericStorage,
                                    kOSAModeNull, &stored);
    }
    if (!error) error = OSALoad(component, &stored, kOSAModeNull, &loaded);
    if (!error) error = OSAExecute(component, loaded, kOSANullScript,
                                  kOSAModeNull, &result);
    if (!error) error = OSACoerceToDesc(component, result, typeSInt32,
                                      kOSAModeNull, &value);
    SInt32 number = 0;
    if (!error) error = AEGetDescData(&value, &number, sizeof(number));
    printf("OSA:status=%d result=%d\n", (int)error, (int)number);
    AEDisposeDesc(&value);
    AEDisposeDesc(&stored);
    AEDisposeDesc(&text);
    if (result) OSADispose(component, result);
    if (loaded) OSADispose(component, loaded);
    if (compiled) OSADispose(component, compiled);
    CloseComponent(component);
    if (argc > 1 && strstr(argv[1], "iokit")) {
        void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW | RTLD_LOCAL);
        if (!iokit) return 9;
        CFMutableDictionaryRef (*matching)(const char *) = dlsym(iokit, "IOServiceMatching");
        io_service_t (*get_service)(mach_port_t, CFDictionaryRef) = dlsym(iokit, "IOServiceGetMatchingService");
        CFTypeRef (*property)(io_registry_entry_t, CFStringRef, CFAllocatorRef, IOOptionBits) = dlsym(iokit, "IORegistryEntryCreateCFProperty");
        kern_return_t (*release)(io_object_t) = dlsym(iokit, "IOObjectRelease");
        if (!matching || !get_service || !property || !release) return 10;
        io_service_t service = get_service(0, matching("IOPlatformExpertDevice"));
        if (!service) return 11;
        CFStringRef key = CFStringCreateWithCString(NULL, "IOPlatformUUID", kCFStringEncodingUTF8);
        CFTypeRef uuid = property(service, key, NULL, 0);
        CFRelease(key);
        char buffer[128] = {0};
        int readable = uuid && CFGetTypeID(uuid) == CFStringGetTypeID() &&
            CFStringGetCString(uuid, buffer, sizeof(buffer), kCFStringEncodingUTF8);
        if (uuid) CFRelease(uuid);
        release(service);
        dlclose(iokit);
        printf("IOKIT:%s uuid=%s\n", readable ? "readable" : "failed", buffer);
        if (!readable) return 12;
    }
    if (argc > 1 && !strncmp(argv[1], "late-application", 16)) {
        if (register_application()) return 6;
    }
    if (image) dlclose(image);
    return error || number != (cold ? 0 : 42);
}
