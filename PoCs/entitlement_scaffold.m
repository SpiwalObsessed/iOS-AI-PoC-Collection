//
//  entitlement_scaffold.m — SCAFFOLD, not an exploit.
//
//  Target : the entitlement/privacy cluster
//           (CVE-2026-112446 Accounts, 112692 App Intents, 86987 Apple
//            Intelligence, 112676 Photos Storage, 112681 Power Management,
//            113914 App Store, 112701 CloudKit, 86925 Quick Look,
//            112685 Siri, 86989 MobileGestalt, 112624 Kernel, ...)
//  Theory : an XPC/IOKit service handler lacked an entitlement or
//           authorization check, so an app without the entitlement could
//           call it and read sensitive data.
//  Status : table-driven tester. It calls each service *without* the
//           relevant entitlement and records whether the call succeeds on
//           27.0.1 vs 27.2. No offsets are needed.
//
//  Build  : xcrun -sdk iphoneos clang -arch arm64 -fobjc-arc \
//              -framework Foundation -framework CoreFoundation \
//              entitlement_scaffold.m -o ent_probe
//

#import <Foundation/Foundation.h>
#include <xpc/xpc.h>

// ---------------------------------------------------------------------------
// Probe table. Each entry is an XPC service name and a message to send.
// The message body is deliberately harmless: we are testing whether the
// connection is accepted and the call is processed, not extracting data.
// ---------------------------------------------------------------------------

typedef struct {
    const char *cve;
    const char *service;      // XPC service / mach service name
    const char *method;       // method key in the message dictionary
} probe_t;

static const probe_t g_probes[] = {
    { "CVE-2026-112446", "com.apple.accountsd",             "accountInfo"      },
    { "CVE-2026-112701", "com.apple.CloudKit",              "containerInfo"    },
    { "CVE-2026-86925",  "com.apple.quicklook.ThumbnailsAgent", "thumbnail"    },
    { "CVE-2026-112685", "com.apple.siri.assistant",        "contextInfo"      },
    { "CVE-2026-86989",  "com.apple.mobilegestalt.xpc",     "gestalt"          },
    { "CVE-2026-113914", "com.apple.AppStore",              "accountState"     },
    { "CVE-2026-112676", "com.apple.photolibraryd",         "libraryInfo"      },
    { "CVE-2026-112681", "com.apple.powerd",                "thermalInfo"      },
};

static const size_t g_probe_count =
    sizeof(g_probes) / sizeof(g_probes[0]);

static void run_probe(const probe_t *p) {
    xpc_connection_t conn = xpc_connection_create_mach_service(
        p->service, NULL, 0);
    if (!conn) {
        printf("[%s] %-45s connection create failed\n", p->cve, p->service);
        return;
    }

    __block int done = 0;
    __block int ok   = 0;
    xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
        if (xpc_get_type(event) == XPC_TYPE_ERROR) {
            done = 1;
            ok = 0;
        } else if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
            done = 1;
            ok = 1;
        }
    });
    xpc_connection_resume(conn);

    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(msg, "method", p->method);
    xpc_dictionary_set_uint64(msg, "version", 1);
    xpc_connection_send_message(conn, msg);

    // Wait up to 2 seconds for a reply or error.
    for (int i = 0; i < 200 && !done; i++) {
        usleep(10 * 1000);
    }

    if (!done) {
        printf("[%s] %-45s NO REPLY (timeout)\n", p->cve, p->service);
    } else if (ok) {
        printf("[%s] %-45s ACCEPTED (reply received) <-- investigate\n",
               p->cve, p->service);
    } else {
        printf("[%s] %-45s rejected\n", p->cve, p->service);
    }

    xpc_connection_cancel(conn);
    xpc_release(conn);
    xpc_release(msg);
}

int main(int argc, char **argv) {
    @autoreleasepool {
        printf("Entitlement probe scaffold (%zu services)\n", g_probe_count);
        printf("Run on 27.0.1 and 27.2; diff the ACCEPTED lines.\n\n");

        for (size_t i = 0; i < g_probe_count; i++) {
            if (argc > 1 && strcmp(argv[1], g_probes[i].cve) != 0) continue;
            run_probe(&g_probes[i]);
        }
    }
    return 0;
}
