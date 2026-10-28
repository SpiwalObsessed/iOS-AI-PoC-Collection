/*
 * cow_integrity_scaffold.c — SCAFFOLD, not an exploit.
 *
 * Target : CVE-2026-112576 (Kernel, copy-on-write memory integrity)
 * Theory : a COW fault path clears the "copy" protection without performing
 *          the private copy for some page states, so a write in one map is
 *          visible in the other. Four variants exercise the anon, file-backed,
 *          madvise and alias paths.
 * Status : behavioural test; needs no offsets. A single variant that differs
 *          between iOS 27.0.1 and 27.2 confirms the bug class.
 *
 * Build  : xcrun -sdk iphoneos clang -arch arm64 cow_integrity_scaffold.c -o cow_test
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <mach/mach.h>

#define PAGE 4096

static int g_failures = 0;

static void check(const char *name, int ok, unsigned char seen) {
    printf("[%s] %-42s expected=0xAA got=0x%02X\n",
           ok ? "PASS" : "FAIL", name, seen);
    if (!ok) g_failures++;
}

/* ------------------------------------------------------------------ */
/* Variant 1: anonymous MAP_PRIVATE, mprotect round-trip.               */
/* ------------------------------------------------------------------ */
static void variant_anon_mprotect(void) {
    unsigned char *p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p == MAP_FAILED) return;
    memset(p, 0xAA, PAGE);

    pid_t child = fork();
    if (child == 0) {
        /* Child waits for parent to do the COW write. */
        usleep(200 * 1000);
        unsigned char seen = p[0];
        check("anon: child sees original after parent write", seen == 0xAA, seen);
        _exit(0);
    }

    /* Parent: toggle protection to force a COW transition, then write. */
    mprotect(p, PAGE, PROT_READ);
    mprotect(p, PAGE, PROT_READ | PROT_WRITE);
    p[0] = 0x55;

    waitpid(child, NULL, 0);
    munmap(p, PAGE);
}

/* ------------------------------------------------------------------ */
/* Variant 2: file-backed MAP_PRIVATE (different pager path).           */
/* ------------------------------------------------------------------ */
static void variant_file_private(void) {
    char path[] = "/tmp/cowtestXXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return;
    unsigned char buf[PAGE];
    memset(buf, 0xAA, PAGE);
    if (write(fd, buf, PAGE) != PAGE) { close(fd); unlink(path); return; }

    unsigned char *p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) { close(fd); unlink(path); return; }

    pid_t child = fork();
    if (child == 0) {
        usleep(200 * 1000);
        unsigned char seen = p[0];
        check("file: child sees original after parent write", seen == 0xAA, seen);
        _exit(0);
    }

    mprotect(p, PAGE, PROT_READ);
    mprotect(p, PAGE, PROT_READ | PROT_WRITE);
    p[0] = 0x55;

    waitpid(child, NULL, 0);
    munmap(p, PAGE);
    close(fd);
    unlink(path);
}

/* ------------------------------------------------------------------ */
/* Variant 3: MADV_FREE_REUSABLE / MADV_PAGEOUT between transitions.    */
/* ------------------------------------------------------------------ */
static void variant_madvise(void) {
    unsigned char *p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p == MAP_FAILED) return;
    memset(p, 0xAA, PAGE);

    pid_t child = fork();
    if (child == 0) {
        usleep(300 * 1000);
        unsigned char seen = p[0];
        check("madvise: child sees original after parent write", seen == 0xAA, seen);
        _exit(0);
    }

    /* Force the page through the pager before and after the COW write. */
    madvise(p, PAGE, MADV_PAGEOUT);
    mprotect(p, PAGE, PROT_READ);
    mprotect(p, PAGE, PROT_READ | PROT_WRITE);
    madvise(p, PAGE, MADV_FREE_REUSABLE);
    p[0] = 0x55;
    madvise(p, PAGE, MADV_FREE_REUSE);

    waitpid(child, NULL, 0);
    munmap(p, PAGE);
}

/* ------------------------------------------------------------------ */
/* Variant 4: alias the page with mach_vm_remap, write via the alias.   */
/* ------------------------------------------------------------------ */
static void variant_alias(void) {
    unsigned char *p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p == MAP_FAILED) return;
    memset(p, 0xAA, PAGE);

    vm_address_t alias = 0;
    vm_size_t sz = PAGE;
    kern_return_t kr = vm_remap(mach_task_self(), &alias, sz, 0,
                                VM_FLAGS_ANYWHERE, mach_task_self(),
                                (vm_address_t)p, FALSE, &sz, VM_INHERIT_NONE);
    if (kr != KERN_SUCCESS) { munmap(p, PAGE); return; }

    pid_t child = fork();
    if (child == 0) {
        usleep(200 * 1000);
        unsigned char seen = p[0];
        check("alias: child sees original after parent write", seen == 0xAA, seen);
        _exit(0);
    }

    /* Write through the alias; with a correct COW model this must NOT
     * become visible through p in the child. */
    mprotect((void *)alias, PAGE, PROT_READ | PROT_WRITE);
    ((unsigned char *)alias)[0] = 0x55;
    p[0] = 0x55;

    waitpid(child, NULL, 0);
    munmap(p, PAGE);
}

int main(void) {
    printf("CVE-2026-112576 COW integrity scaffold\n");
    printf("A FAIL line means the COW invariant was violated on THIS build.\n\n");

    variant_anon_mprotect();
    variant_file_private();
    variant_madvise();
    variant_alias();

    printf("\n%s (%d invariant violation(s))\n",
           g_failures ? "COW INVARIANT VIOLATED" : "COW invariant held",
           g_failures);
    return g_failures ? 1 : 0;
}
