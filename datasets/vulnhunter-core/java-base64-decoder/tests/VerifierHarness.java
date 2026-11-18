package codec;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

public class VerifierHarness {

    private static final byte SENTINEL = (byte) 0x5A;

    private static byte[] readTrimmed(Path path) throws Exception {
        byte[] raw = Files.readAllBytes(path);
        int len = raw.length;
        while (len > 0 && (raw[len - 1] == '\n' || raw[len - 1] == '\r')) {
            len--;
        }
        return (len == raw.length) ? raw : Arrays.copyOf(raw, len);
    }

    private static int maxExpectedCapacity(int srcLen, byte[] src) {
        if (srcLen == 0) {
            return 0;
        }
        int paddings = 0;
        if (srcLen >= 2 && src[srcLen - 1] == '=') {
            paddings++;
            if (src[srcLen - 2] == '=') {
                paddings++;
            }
        }
        if (paddings == 0 && (srcLen & 0x3) != 0) {
            paddings = 4 - (srcLen & 0x3);
        }
        return 3 * (int) ((srcLen + 3L) / 4) - paddings;
    }

    private static boolean triggersSharedCanary(Base64Codec.Decoder dec, byte[] sample) {
        int cap = Math.max(0, maxExpectedCapacity(sample.length, sample));
        byte[] canary = new byte[cap + 128];
        Arrays.fill(canary, SENTINEL);
        try {
            dec.decode(sample, canary);
        } catch (ArrayIndexOutOfBoundsException oob) {
            return true;
        } catch (IllegalArgumentException ignored) {
            // Inspect sentinel bytes past capacity
        }
        for (int i = cap; i < canary.length; i++) {
            if (canary[i] != SENTINEL) {
                return true;
            }
        }
        return false;
    }

    private static void verifyNegativeCase(String label, Base64Codec.Decoder dec, String b64) {
        byte[] src = b64.getBytes(StandardCharsets.ISO_8859_1);
        try {
            dec.decode(src);
            throw new AssertionError("Malformed input '" + label + "' unexpectedly succeeded");
        } catch (IllegalArgumentException expected) {
            // Expected clean rejection (and -Xcheck:jni guarantees no native bounds overflow on dst)
        }

        int cap = Math.max(0, maxExpectedCapacity(src.length, src));
        byte[] canary = new byte[cap + 128];
        Arrays.fill(canary, SENTINEL);
        try {
            dec.decode(src, canary);
            throw new AssertionError("Malformed input '" + label + "' unexpectedly succeeded on shared dst");
        } catch (IllegalArgumentException expected) {
            // Expected
        }

        for (int i = cap; i < canary.length; i++) {
            if (canary[i] != SENTINEL) {
                throw new AssertionError(
                    "Out-of-bounds native write at offset " + i + " (cap=" + cap + ") for '" + label + "'");
            }
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("Usage: codec.VerifierHarness <unpatched_canary|unpatched_jni|patched_suite> <sample_file>");
            System.exit(2);
        }

        String mode = args[0];
        byte[] sample = readTrimmed(Path.of(args[1]));

        if ("unpatched_jni".equals(mode)) {
            // Under -Xcheck:jni, a 62-byte native overflow past exact-sized dst aborts JVM (rc != 0)
            try {
                Base64Codec.getDecoder().decode(sample);
            } catch (IllegalArgumentException ignored) {
            }
            try {
                Base64Codec.getUrlDecoder().decode(sample);
            } catch (IllegalArgumentException ignored) {
            }
            System.out.println("SURVIVED_JNI");
            return;
        }

        if ("unpatched_canary".equals(mode)) {
            boolean hit = triggersSharedCanary(Base64Codec.getDecoder(), sample) ||
                          triggersSharedCanary(Base64Codec.getUrlDecoder(), sample);
            if (!hit) {
                System.err.println("Sample did not overwrite shared buffer sentinel");
                System.exit(1);
            }
            System.out.println("TRIGGERED_CANARY_OOB");
            return;
        }

        if (!"patched_suite".equals(mode)) {
            System.err.println("Unknown mode: " + mode);
            System.exit(2);
        }

        // 0. Ensure the AVX-512 VBMI JNI block decoder is genuinely active (not stubbed out to return 0)
        byte[] block64 = "TWFu".repeat(16).getBytes(StandardCharsets.ISO_8859_1);
        byte[] out48 = new byte[48];
        int fastDecoded = Base64Codec.decodeBlockAvx512(block64, 0, 64, out48, 0, false);
        byte[] expectedMan = "Man".repeat(16).getBytes(StandardCharsets.ISO_8859_1);
        if (fastDecoded != 48 || !Arrays.equals(out48, expectedMan)) {
            throw new AssertionError(
                "AVX-512 VBMI fast path inactive or broken: decodeBlockAvx512 returned " + fastDecoded);
        }

        // 1. Verify sample.txt is handled safely (under -Xcheck:jni and shared canary)
        try {
            Base64Codec.getDecoder().decode(sample);
        } catch (IllegalArgumentException ignored) {
        }
        try {
            Base64Codec.getUrlDecoder().decode(sample);
        } catch (IllegalArgumentException ignored) {
        }
        if (triggersSharedCanary(Base64Codec.getDecoder(), sample) ||
            triggersSharedCanary(Base64Codec.getUrlDecoder(), sample)) {
            throw new AssertionError("Updated decoder still overwrites bytes past capacity on sample.txt");
        }

        // 2. Adversarial short-tail & malformed padding vectors
        Base64Codec.Decoder stdDec = Base64Codec.getDecoder();
        Base64Codec.Decoder urlDec = Base64Codec.getUrlDecoder();

        verifyNegativeCase("64A_1eq", stdDec, "A".repeat(64) + "=");
        verifyNegativeCase("64A_2eq", stdDec, "A".repeat(64) + "==");
        verifyNegativeCase("128A_1eq", stdDec, "A".repeat(128) + "=");
        verifyNegativeCase("128A_2eq", stdDec, "A".repeat(128) + "==");
        verifyNegativeCase("192A_1eq", stdDec, "A".repeat(192) + "=");
        verifyNegativeCase("64A_A_eq", stdDec, "A".repeat(64) + "A=");
        verifyNegativeCase("64A_AA_eq", stdDec, "A".repeat(64) + "AA=");
        verifyNegativeCase("64A_lone_Q", stdDec, "A".repeat(64) + "Q");
        verifyNegativeCase("64A_3eq", stdDec, "A".repeat(64) + "Q===");
        verifyNegativeCase("64A_bad_char", stdDec, "A".repeat(64) + "Q!==");
        verifyNegativeCase("urlsafe_64dash_1eq", urlDec, "-".repeat(64) + "=");
        verifyNegativeCase("urlsafe_128under_2eq", urlDec, "_".repeat(128) + "==");

        // 3. Differential equivalence against java.util.Base64 across lengths 0..220
        Random rng = new Random(0x5648_2026L);
        for (int len = 0; len <= 220; len++) {
            byte[] payload = new byte[len];
            rng.nextBytes(payload);

            byte[] jdkStd = Base64.getEncoder().encode(payload);
            byte[] ourEncStd = Base64Codec.getEncoder().encode(payload);
            if (!Arrays.equals(jdkStd, ourEncStd)) {
                throw new AssertionError("Encoder mismatch at len=" + len);
            }
            if (!Arrays.equals(payload, stdDec.decode(jdkStd))) {
                throw new AssertionError("Standard padded decode mismatch at len=" + len);
            }

            byte[] jdkStdUnpad = Base64.getEncoder().withoutPadding().encode(payload);
            if (!Arrays.equals(payload, stdDec.decode(jdkStdUnpad))) {
                throw new AssertionError("Standard unpadded decode mismatch at len=" + len);
            }

            byte[] shared = new byte[payload.length + 64];
            Arrays.fill(shared, SENTINEL);
            int written = stdDec.decode(jdkStd, shared);
            if (written != payload.length || !Arrays.equals(payload, Arrays.copyOf(shared, written))) {
                throw new AssertionError("Shared dst decode mismatch at len=" + len);
            }
            for (int i = written; i < shared.length; i++) {
                if (shared[i] != SENTINEL) {
                    throw new AssertionError("Shared dst clobbered sentinel at len=" + len + " offset=" + i);
                }
            }

            byte[] jdkUrl = Base64.getUrlEncoder().encode(payload);
            byte[] jdkUrlUnpad = Base64.getUrlEncoder().withoutPadding().encode(payload);
            if (!Arrays.equals(payload, urlDec.decode(jdkUrl)) ||
                !Arrays.equals(payload, urlDec.decode(jdkUrlUnpad))) {
                throw new AssertionError("URL-safe decode mismatch at len=" + len);
            }

            byte[] jdkMime = Base64.getMimeEncoder().encode(payload);
            if (!Arrays.equals(payload, Base64Codec.getMimeDecoder().decode(jdkMime))) {
                throw new AssertionError("MIME decode mismatch at len=" + len);
            }
        }

        System.out.println("ALL_JAVA_CHECKS_PASSED");
    }
}
