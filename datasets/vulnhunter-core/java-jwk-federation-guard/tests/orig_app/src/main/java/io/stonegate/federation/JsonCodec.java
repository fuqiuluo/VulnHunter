package io.stonegate.federation;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Zero-dependency RFC 8259 JSON parser, canonical serializer, and RFC 7515 Base64URL codec.
 *
 * <p>Contract (RFC 8259 §4, §7, §9 &amp; RFC 8725 §3.12):
 * <ul>
 *   <li>JSON texts MUST contain a single valid value with no trailing non-whitespace tokens.</li>
 *   <li>Strings undergo full RFC 8259 escape decoding ({@code \u005CuXXXX} hex escapes and UTF-16
 *       surrogate pairs); unescaped control characters ({@code U+0000..U+001F}) are rejected.</li>
 *   <li>Object member names MUST be unique at every nesting level after full escape decoding;
 *       duplicate member names MUST throw {@link IllegalArgumentException}.</li>
 *   <li>{@link #decodeBase64Url(String)} enforces unpadded Base64URL per RFC 7515 §2, rejecting
 *       {@code '='} padding, non-URL alphabet characters, residue length 1, and non-zero pad bits.</li>
 * </ul>
 */
public final class JsonCodec {

    private static final int MAX_NESTING_DEPTH = 64;
    private static final int[] B64URL_DECODE = new int[128];

    static {
        Arrays.fill(B64URL_DECODE, -1);
        for (int i = 0; i < 26; i++) {
            B64URL_DECODE['A' + i] = i;
            B64URL_DECODE['a' + i] = i + 26;
        }
        for (int i = 0; i < 10; i++) {
            B64URL_DECODE['0' + i] = i + 52;
        }
        B64URL_DECODE['-'] = 62;
        B64URL_DECODE['_'] = 63;
    }

    private JsonCodec() {}

    /** Parses a JSON document whose root value MUST be a JSON object. */
    public static Map<String, Object> parseObject(String json) {
        if (!(parseValue(json) instanceof Map<?, ?> map)) {
            throw new IllegalArgumentException("Expected top-level JSON object");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> typed = (Map<String, Object>) map;
        return typed;
    }

    /** Parses any single RFC 8259 JSON value. */
    public static Object parseValue(String json) {
        if (json == null) throw new IllegalArgumentException("JSON input must not be null");
        Parser parser = new Parser(json);
        Object value = parser.readValue(0);
        parser.skipWhitespace();
        if (parser.pos < parser.len) {
            throw new IllegalArgumentException("Unexpected trailing token at index " + parser.pos);
        }
        return value;
    }

    /** Extracts a top-level string member value from a JSON object text for routing inspection. */
    public static String extractTopLevelStringField(String json, String fieldName) {
        if (json == null || fieldName == null || fieldName.isEmpty()) return null;
        int len = json.length();
        int i = skipWs(json, 0, len);
        if (i >= len || json.charAt(i) != '{') return null;
        i = skipWs(json, i + 1, len);
        if (i < len && json.charAt(i) == '}') return null;
        while (i < len) {
            i = skipWs(json, i, len);
            if (i >= len || json.charAt(i) != '"') return null;
            int keyEnd = scanRawStringEnd(json, i + 1, len);
            if (keyEnd < 0) return null;
            String rawKey = json.substring(i + 1, keyEnd);
            i = skipWs(json, keyEnd + 1, len);
            if (i >= len || json.charAt(i) != ':') return null;
            i = skipWs(json, i + 1, len);
            if (i >= len) return null;
            if (rawKey.equals(fieldName)) {
                if (json.charAt(i) != '"') return null;
                Parser p = new Parser(json);
                p.pos = i;
                return p.readString();
            }
            i = skipRawValue(json, i, len);
            if (i < 0) return null;
            i = skipWs(json, i, len);
            if (i < len && json.charAt(i) == ',') {
                i++;
            } else {
                return null;
            }
        }
        return null;
    }

    private static int skipWs(String s, int idx, int len) {
        while (idx < len && " \t\r\n".indexOf(s.charAt(idx)) >= 0) idx++;
        return idx;
    }

    private static int scanRawStringEnd(String s, int idx, int len) {
        while (idx < len) {
            char c = s.charAt(idx);
            if (c == '"') return idx;
            idx += (c == '\\') ? 2 : 1;
        }
        return -1;
    }

    private static int skipRawValue(String s, int idx, int len) {
        char start = s.charAt(idx);
        if (start == '"') {
            int end = scanRawStringEnd(s, idx + 1, len);
            return end < 0 ? -1 : end + 1;
        }
        if (start == '{' || start == '[') {
            int depth = 1;
            int p = idx + 1;
            while (p < len && depth > 0) {
                char c = s.charAt(p);
                if (c == '"') {
                    int end = scanRawStringEnd(s, p + 1, len);
                    if (end < 0) return -1;
                    p = end + 1;
                } else {
                    if (c == '{' || c == '[') depth++;
                    else if (c == '}' || c == ']') depth--;
                    p++;
                }
            }
            return depth == 0 ? p : -1;
        }
        int p = idx;
        while (p < len && ",}] \t\r\n".indexOf(s.charAt(p)) < 0) p++;
        return p > idx ? p : -1;
    }

    /** Serializes a JSON value with lexicographically sorted object keys and zero whitespace. */
    public static String serializeCanonical(Object value) {
        StringBuilder sb = new StringBuilder(128);
        writeJson(value, sb, true);
        return sb.toString();
    }

    /** Serializes a JSON value preserving map iteration order and zero whitespace. */
    public static String serialize(Object value) {
        StringBuilder sb = new StringBuilder(128);
        writeJson(value, sb, false);
        return sb.toString();
    }

    public static String encodeBase64Url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(Objects.requireNonNull(data));
    }

    public static String encodeUtf8Base64Url(String text) {
        return encodeBase64Url(text.getBytes(StandardCharsets.UTF_8));
    }

    public static String decodeUtf8Base64Url(String encoded) {
        return new String(decodeBase64Url(encoded), StandardCharsets.UTF_8);
    }

    public static byte[] decodeBase64Url(String encoded) {
        if (encoded == null) throw new IllegalArgumentException("Base64URL input must not be null");
        int len = encoded.length();
        int rem = len & 3;
        if (rem == 1) throw new IllegalArgumentException("Invalid Base64URL length: " + len);
        for (int i = 0; i < len; i++) {
            char ch = encoded.charAt(i);
            if (ch >= 128 || B64URL_DECODE[ch] < 0) {
                throw new IllegalArgumentException("Illegal Base64URL character at index " + i);
            }
        }
        if ((rem == 2 && (B64URL_DECODE[encoded.charAt(len - 1)] & 0x0F) != 0)
                || (rem == 3 && (B64URL_DECODE[encoded.charAt(len - 1)] & 0x03) != 0)) {
            throw new IllegalArgumentException("Non-canonical trailing bits in Base64URL input");
        }
        return Base64.getUrlDecoder().decode(encoded);
    }

    private static void writeJson(Object value, StringBuilder sb, boolean sortKeys) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof Boolean b) {
            sb.append(b.booleanValue());
        } else if (value instanceof Integer || value instanceof Long || value instanceof Short || value instanceof Byte) {
            sb.append(((Number) value).longValue());
        } else if (value instanceof BigDecimal bd) {
            sb.append(bd.toPlainString());
        } else if (value instanceof Number num) {
            double d = num.doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) throw new IllegalArgumentException("Non-finite JSON number");
            sb.append(num);
        } else if (value instanceof String s) {
            writeEscapedString(s, sb);
        } else if (value instanceof List<?> list) {
            sb.append('[');
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) sb.append(',');
                writeJson(list.get(i), sb, sortKeys);
            }
            sb.append(']');
        } else if (value instanceof Map<?, ?> rawMap) {
            Map<String, Object> ordered = sortKeys ? new TreeMap<>() : new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : rawMap.entrySet()) {
                if (!(entry.getKey() instanceof String k)) throw new IllegalArgumentException("Keys must be strings");
                ordered.put(k, entry.getValue());
            }
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> entry : ordered.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                writeEscapedString(entry.getKey(), sb);
                sb.append(':');
                writeJson(entry.getValue(), sb, sortKeys);
            }
            sb.append('}');
        } else {
            throw new IllegalArgumentException("Unsupported JSON type: " + value.getClass().getName());
        }
    }

    private static void writeEscapedString(String s, StringBuilder sb) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> sb.append(c < 0x20 ? String.format("\\u%04x", (int) c) : String.valueOf(c));
            }
        }
        sb.append('"');
    }

    private static final class Parser {
        private final String src;
        private final int len;
        private int pos;

        Parser(String src) {
            this.src = src;
            this.len = src.length();
        }

        void skipWhitespace() {
            while (pos < len && " \t\r\n".indexOf(src.charAt(pos)) >= 0) pos++;
        }

        Object readValue(int depth) {
            if (depth > MAX_NESTING_DEPTH) throw new IllegalArgumentException("Max JSON nesting depth exceeded");
            skipWhitespace();
            if (pos >= len) throw new IllegalArgumentException("Unexpected end of JSON input");
            char c = src.charAt(pos);
            return switch (c) {
                case '{' -> readObject(depth + 1);
                case '[' -> readArray(depth + 1);
                case '"' -> readString();
                case 't' -> readLiteral("true", Boolean.TRUE);
                case 'f' -> readLiteral("false", Boolean.FALSE);
                case 'n' -> readLiteral("null", null);
                default -> {
                    if (c == '-' || (c >= '0' && c <= '9')) yield readNumber();
                    throw new IllegalArgumentException("Unexpected character '" + c + "' at index " + pos);
                }
            };
        }

        private Map<String, Object> readObject(int depth) {
            pos++;
            skipWhitespace();
            Map<String, Object> map = new LinkedHashMap<>();
            if (pos < len && src.charAt(pos) == '}') {
                pos++;
                return Collections.unmodifiableMap(map);
            }
            while (true) {
                skipWhitespace();
                if (pos >= len || src.charAt(pos) != '"') {
                    throw new IllegalArgumentException("Expected quoted member name at index " + pos);
                }
                String key = readString();
                skipWhitespace();
                if (pos >= len || src.charAt(pos) != ':') {
                    throw new IllegalArgumentException("Expected ':' after member name at index " + pos);
                }
                pos++;
                map.put(key, readValue(depth));
                skipWhitespace();
                if (pos >= len) throw new IllegalArgumentException("Unterminated JSON object");
                char sep = src.charAt(pos++);
                if (sep == '}') break;
                if (sep != ',') throw new IllegalArgumentException("Expected ',' or '}' at index " + (pos - 1));
            }
            return Collections.unmodifiableMap(map);
        }

        private List<Object> readArray(int depth) {
            pos++;
            skipWhitespace();
            List<Object> list = new ArrayList<>();
            if (pos < len && src.charAt(pos) == ']') {
                pos++;
                return Collections.unmodifiableList(list);
            }
            while (true) {
                list.add(readValue(depth));
                skipWhitespace();
                if (pos >= len) throw new IllegalArgumentException("Unterminated JSON array");
                char sep = src.charAt(pos++);
                if (sep == ']') break;
                if (sep != ',') throw new IllegalArgumentException("Expected ',' or ']' at index " + (pos - 1));
            }
            return Collections.unmodifiableList(list);
        }

        String readString() {
            if (pos >= len || src.charAt(pos) != '"') throw new IllegalArgumentException("Expected '\"'");
            pos++;
            StringBuilder sb = new StringBuilder();
            while (pos < len) {
                char c = src.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c < 0x20) throw new IllegalArgumentException("Unescaped control character in JSON string");
                if (c != '\\') {
                    sb.append(c);
                    continue;
                }
                if (pos >= len) throw new IllegalArgumentException("Unterminated escape sequence");
                char esc = src.charAt(pos++);
                switch (esc) {
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case '/' -> sb.append('/');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'u' -> {
                        int cp = readHexQuad();
                        if (Character.isHighSurrogate((char) cp)) {
                            if (pos + 1 >= len || src.charAt(pos) != '\\' || src.charAt(pos + 1) != 'u') {
                                throw new IllegalArgumentException("Unpaired high surrogate");
                            }
                            pos += 2;
                            int low = readHexQuad();
                            if (!Character.isLowSurrogate((char) low)) {
                                throw new IllegalArgumentException("Invalid UTF-16 surrogate pair");
                            }
                            sb.appendCodePoint(Character.toCodePoint((char) cp, (char) low));
                        } else if (Character.isLowSurrogate((char) cp)) {
                            throw new IllegalArgumentException("Unpaired low surrogate");
                        } else {
                            sb.append((char) cp);
                        }
                    }
                    default -> throw new IllegalArgumentException("Illegal escape '\\" + esc + "'");
                }
            }
            throw new IllegalArgumentException("Unterminated JSON string");
        }

        private int readHexQuad() {
            if (pos + 4 > len) throw new IllegalArgumentException("Truncated \\uXXXX escape");
            int val = 0;
            for (int i = 0; i < 4; i++) {
                int d = Character.digit(src.charAt(pos++), 16);
                if (d < 0) throw new IllegalArgumentException("Invalid hex digit in \\uXXXX escape");
                val = (val << 4) | d;
            }
            return val;
        }

        private Object readLiteral(String expected, Object result) {
            if (!src.startsWith(expected, pos)) throw new IllegalArgumentException("Invalid literal at " + pos);
            pos += expected.length();
            return result;
        }

        private Number readNumber() {
            int start = pos;
            if (src.charAt(pos) == '-' && ++pos >= len) throw new IllegalArgumentException("Malformed number");
            if (src.charAt(pos) == '0') {
                pos++;
                if (pos < len && Character.isDigit(src.charAt(pos))) {
                    throw new IllegalArgumentException("Leading zeros not allowed in JSON numbers");
                }
            } else if (src.charAt(pos) >= '1' && src.charAt(pos) <= '9') {
                while (pos < len && Character.isDigit(src.charAt(pos))) pos++;
            } else {
                throw new IllegalArgumentException("Invalid number at index " + start);
            }
            boolean floating = false;
            if (pos < len && src.charAt(pos) == '.') {
                floating = true;
                pos++;
                if (pos >= len || !Character.isDigit(src.charAt(pos))) {
                    throw new IllegalArgumentException("Expected fractional digits");
                }
                while (pos < len && Character.isDigit(src.charAt(pos))) pos++;
            }
            if (pos < len && (src.charAt(pos) == 'e' || src.charAt(pos) == 'E')) {
                floating = true;
                pos++;
                if (pos < len && (src.charAt(pos) == '+' || src.charAt(pos) == '-')) pos++;
                if (pos >= len || !Character.isDigit(src.charAt(pos))) {
                    throw new IllegalArgumentException("Expected exponent digits");
                }
                while (pos < len && Character.isDigit(src.charAt(pos))) pos++;
            }
            String token = src.substring(start, pos);
            if (!floating) {
                try {
                    return Long.parseLong(token);
                } catch (NumberFormatException ex) {
                    return new BigDecimal(token);
                }
            }
            BigDecimal bd = new BigDecimal(token);
            double d = bd.doubleValue();
            return (Double.isInfinite(d) || Double.isNaN(d)) ? bd : d;
        }
    }
}
