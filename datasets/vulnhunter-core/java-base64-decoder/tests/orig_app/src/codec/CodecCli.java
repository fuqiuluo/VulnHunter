package codec;

import java.nio.file.Files;
import java.nio.file.Path;

public class CodecCli {

    private static long fnv1a64(byte[] data) {
        long hash = 0xcbf29ce484222325L;
        for (byte b : data) {
            hash ^= (b & 0xffL);
            hash *= 0x100000001b3L;
        }
        return hash;
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: b64_cli <input_file>");
            System.exit(1);
        }

        byte[] raw = Files.readAllBytes(Path.of(args[0]));
        int len = raw.length;
        while (len > 0 && (raw[len - 1] == '\n' || raw[len - 1] == '\r')) {
            len--;
        }
        if (len != raw.length) {
            byte[] trimmed = new byte[len];
            System.arraycopy(raw, 0, trimmed, 0, len);
            raw = trimmed;
        }

        try {
            byte[] decoded = Base64Codec.getDecoder().decode(raw);
            System.out.printf("OK bytes=%d fnv1a=%016x%n", decoded.length, fnv1a64(decoded));
            System.exit(0);
        } catch (IllegalArgumentException ex) {
            System.err.println("INVALID: " + ex.getMessage());
            System.exit(1);
        }
    }
}
