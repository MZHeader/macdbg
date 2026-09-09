#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define UTF8_ENCODING 0x08000100U

typedef void *(*service_matching_fn)(const char *);
typedef uint32_t (*get_matching_service_fn)(uint32_t, void *);
typedef const void *(*create_property_fn)(uint32_t, const void *,
                                          const void *, uint32_t);
typedef int (*object_release_fn)(uint32_t);
typedef const void *(*cfstring_create_fn)(const void *, const char *, uint32_t);
typedef unsigned char (*cfstring_get_fn)(const void *, char *, long, uint32_t);
typedef void (*cf_release_fn)(const void *);

static int copy_property(create_property_fn create_property,
                         cfstring_create_fn make_string,
                         cfstring_get_fn get_string,
                         cf_release_fn release,
                         uint32_t service,
                         const char *name,
                         char *output,
                         size_t output_size) {
    const void *key = make_string(NULL, name, UTF8_ENCODING);
    if (!key) return 0;
    const void *value = create_property(service, key, NULL, 0);
    release(key);
    if (!value) return 0;
    int copied = get_string(value, output, (long)output_size, UTF8_ENCODING);
    release(value);
    return copied;
}

int main(void) {
    void *iokit = dlopen(
        "/System/Library/Frameworks/IOKit.framework/IOKit",
        RTLD_NOW | RTLD_LOCAL);
    if (!iokit) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 2;
    }

    service_matching_fn service_matching =
        (service_matching_fn)dlsym(iokit, "IOServiceMatching");
    get_matching_service_fn get_matching_service =
        (get_matching_service_fn)dlsym(iokit, "IOServiceGetMatchingService");
    create_property_fn create_property =
        (create_property_fn)dlsym(iokit,
            "IORegistryEntryCreateCFProperty");
    object_release_fn object_release =
        (object_release_fn)dlsym(iokit, "IOObjectRelease");
    cfstring_create_fn make_string =
        (cfstring_create_fn)dlsym(RTLD_DEFAULT,
            "CFStringCreateWithCString");
    cfstring_get_fn get_string =
        (cfstring_get_fn)dlsym(RTLD_DEFAULT, "CFStringGetCString");
    cf_release_fn release =
        (cf_release_fn)dlsym(RTLD_DEFAULT, "CFRelease");
    if (!service_matching || !get_matching_service || !create_property ||
        !object_release || !make_string || !get_string || !release) {
        dlclose(iokit);
        return 3;
    }

    uint32_t service = get_matching_service(
        0, service_matching("IOPlatformExpertDevice"));
    char serial[128] = {0};
    char uuid[128] = {0};
    int readable = service &&
        copy_property(create_property, make_string, get_string, release,
                      service, "IOPlatformSerialNumber",
                      serial, sizeof(serial)) &&
        copy_property(create_property, make_string, get_string, release,
                      service, "IOPlatformUUID", uuid, sizeof(uuid));
    if (service) object_release(service);
    dlclose(iokit);

    int bad = !readable || strcmp(serial, "C02ZQ0ABC123") ||
              strcmp(uuid, "8D4C7A12-3F65-4B90-A2DE-61C8E5079F34");
    printf("LATE-IOKIT:%s serial=%s uuid=%s\n",
           bad ? "DETECTED" : "clean", serial, uuid);
    return bad;
}
