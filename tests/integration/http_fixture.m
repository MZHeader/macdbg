#import <Foundation/Foundation.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* The HTTPS test uses an ephemeral self-signed certificate on loopback only. */
@interface LocalTestTrustDelegate : NSObject <NSURLSessionDelegate>
@end

@implementation LocalTestTrustDelegate
- (void)URLSession:(NSURLSession *)session
    didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
    completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completion {
    (void)session;
    NSURLProtectionSpace *space = challenge.protectionSpace;
    if ([space.host isEqualToString:@"127.0.0.1"]
        && [space.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]
        && space.serverTrust != NULL) {
        completion(NSURLSessionAuthChallengeUseCredential,
                   [NSURLCredential credentialForTrust:space.serverTrust]);
    } else {
        completion(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}
@end

/* Every request is synthetic and restricted to the local test server. */
static NSData *form_body(void) {
    NSString *padding = [@"" stringByPaddingToLength:2048 withString:@"x" startingAtIndex:0];
    NSString *form = [@"tag=one&tag=two&message=hello+world%26test&padding="
                     stringByAppendingString:padding];
    return [form dataUsingEncoding:NSUTF8StringEncoding];
}

static NSData *json_body(void) {
    NSString *padding = [@"" stringByPaddingToLength:2048 withString:@"y" startingAtIndex:0];
    NSString *json = [NSString stringWithFormat:
                     @"{\"kind\":\"upload\",\"message\":\"synthetic local request\",\"padding\":\"%@\"}",
                     padding];
    return [json dataUsingEncoding:NSUTF8StringEncoding];
}

static int session_post(NSString *mode, NSURL *url) {
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST";
    [request setValue:@"synthetic-local-only" forHTTPHeaderField:@"X-MacDBG-Fixture"];
    [request setValue:@"Bearer test-token" forHTTPHeaderField:@"Authorization"];
    BOOL upload = [mode isEqualToString:@"upload-json"];
    NSData *body = upload ? json_body() : form_body();
    [request setValue:upload ? @"application/json" : @"application/x-www-form-urlencoded"
        forHTTPHeaderField:@"Content-Type"];

    if ([mode isEqualToString:@"stream-form"]) {
        request.HTTPBodyStream = [NSInputStream inputStreamWithData:body];
        [request setValue:[NSString stringWithFormat:@"%lu", (unsigned long)body.length]
            forHTTPHeaderField:@"Content-Length"];
    } else if (upload) {
        /* fromData is the transmitted payload, even when HTTPBody disagrees. */
        request.HTTPBody = [@"incorrect-request-body" dataUsingEncoding:NSUTF8StringEncoding];
    } else {
        request.HTTPBody = body;
    }

    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    configuration.timeoutIntervalForRequest = 45;
    configuration.connectionProxyDictionary = @{};
    LocalTestTrustDelegate *trust = [mode isEqualToString:@"data-https"]
        ? [LocalTestTrustDelegate new] : nil;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration
                             delegate:trust delegateQueue:nil];
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block int result = 1;
    void (^completion)(NSData *, NSURLResponse *, NSError *) =
        ^(NSData *data, NSURLResponse *response, NSError *error) {
            (void)data;
            NSInteger status = [(NSHTTPURLResponse *)response statusCode];
            result = error == nil && status == 200 ? 0 : 1;
            printf("HTTP-FIXTURE:%s status=%ld error=%s\n", result ? "failed" : "ok",
                   (long)status, error ? error.localizedDescription.UTF8String : "none");
            dispatch_semaphore_signal(done);
        };
    NSURLSessionTask *task;
    if (upload) {
        task = [session uploadTaskWithRequest:request fromData:body completionHandler:completion];
    } else {
        task = [session dataTaskWithRequest:request completionHandler:completion];
    }
    [task resume];
    if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 60 * NSEC_PER_SEC))) {
        fprintf(stderr, "HTTP-FIXTURE:timeout\n");
        [session invalidateAndCancel];
        return 2;
    }
    [session finishTasksAndInvalidate];
    return result;
}

static int write_all(int fd, const void *bytes, size_t count, int use_write) {
    const char *cursor = bytes;
    while (count) {
        ssize_t sent = use_write ? write(fd, cursor, count) : send(fd, cursor, count, 0);
        if (sent < 0 && errno == EINTR) continue;
        if (sent <= 0) return -1;
        cursor += sent;
        count -= (size_t)sent;
    }
    return 0;
}

static int raw_post(NSURL *url) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 3;
    struct sockaddr_in address = {0};
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)url.port.unsignedIntValue);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        perror("connect");
        close(fd);
        return 3;
    }
    NSData *body = form_body();
    NSString *head = [NSString stringWithFormat:
                     @"POST %@ HTTP/1.1\r\nHost: 127.0.0.1:%@\r\n"
                     @"X-MacDBG-Fixture: synthetic-local-only\r\n"
                     @"Content-Type: application/x-www-form-urlencoded\r\n"
                     @"Content-Length: %lu\r\nConnection: close\r\n\r\n",
                     url.path, url.port, (unsigned long)body.length];
    NSData *header = [head dataUsingEncoding:NSUTF8StringEncoding];
    const char *header_bytes = header.bytes;
    const char *body_bytes = body.bytes;
    /* Header delimiter and body both cross send/write boundaries. */
    int result = write_all(fd, header_bytes, 19, 0)
        || write_all(fd, header_bytes + 19, header.length - 21, 1)
        || write_all(fd, header_bytes + header.length - 2, 2, 0)
        || write_all(fd, body_bytes, 701, 1)
        || write_all(fd, body_bytes + 701, body.length - 701, 0);
    char reply[256] = {0};
    ssize_t received = result ? -1 : recv(fd, reply, sizeof(reply) - 1, 0);
    close(fd);
    if (received <= 0 || !strstr(reply, " 200 ")) {
        fprintf(stderr, "HTTP-FIXTURE:raw failed\n");
        return 4;
    }
    puts("HTTP-FIXTURE:ok raw");
    return 0;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 3) return 64;
        NSString *mode = [NSString stringWithUTF8String:argv[1]];
        NSURL *url = [NSURL URLWithString:[NSString stringWithUTF8String:argv[2]]];
        BOOL local_scheme = [url.scheme isEqualToString:@"http"]
            || ([mode isEqualToString:@"data-https"] && [url.scheme isEqualToString:@"https"]);
        if (!local_scheme || ![url.host isEqualToString:@"127.0.0.1"]
            || url.port == nil) return 64;
        if ([mode isEqualToString:@"raw-http"]) return raw_post(url);
        if ([mode isEqualToString:@"data-form"] || [mode isEqualToString:@"upload-json"]
            || [mode isEqualToString:@"stream-form"] || [mode isEqualToString:@"data-https"])
            return session_post(mode, url);
        return 64;
    }
}
