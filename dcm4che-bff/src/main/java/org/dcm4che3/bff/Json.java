/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is part of dcm4che, an implementation of DICOM(TM) in
 * Java(TM), hosted at https://github.com/gunterze/dcm4che.
 *
 * The Initial Developer of the Original Code is
 * Agfa Healthcare.
 * Portions created by the Initial Developer are Copyright (C) 2011-2014
 * the Initial Developer. All Rights Reserved.
 *
 * ***** END LICENSE BLOCK ***** */

package org.dcm4che3.bff;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.Iterator;
import java.util.Map;

/**
 * Small JSON parser, sufficient for OpenID Connect discovery documents, token
 * responses and the claims of JSON Web Tokens. Objects are mapped to
 * <code>Map&lt;String, Object&gt;</code>, arrays to <code>Object[]</code>, numbers
 * to {@link Long} or {@link Double}, booleans to {@link Boolean} and JSON null to
 * <code>null</code>.
 * <p>
 * The parser is deliberately strict: trailing content is rejected, and nesting is
 * limited to protect against malicious responses.
 *
 * @author dcm4che
 */
public final class Json {

    private static final int MAX_DEPTH = 64;
    private static final Charset UTF_8 = Charset.forName("UTF-8");

    private final String s;
    private int pos;

    private Json(String s) {
        this.s = s;
    }

    /**
     * Parses a JSON document.
     *
     * @throws IOException if the document is not valid JSON
     */
    public static Object parse(String json) throws IOException {
        if (json == null)
            throw new IOException("Empty JSON document");
        Json parser = new Json(json);
        parser.skipWhitespace();
        Object value = parser.parseValue(0);
        parser.skipWhitespace();
        if (parser.pos != json.length())
            throw parser.error("Trailing content");
        return value;
    }

    /**
     * Parses a JSON document that must be an object.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String json) throws IOException {
        Object value = parse(json);
        if (!(value instanceof Map))
            throw new IOException("Expected JSON object");
        return (Map<String, Object>) value;
    }

    private Object parseValue(int depth) throws IOException {
        if (depth > MAX_DEPTH)
            throw error("Nesting too deep");
        if (pos >= s.length())
            throw error("Unexpected end of document");
        char c = s.charAt(pos);
        switch (c) {
        case '{':
            return parseObjectValue(depth);
        case '[':
            return parseArray(depth);
        case '"':
            return parseString();
        case 't':
            expect("true");
            return Boolean.TRUE;
        case 'f':
            expect("false");
            return Boolean.FALSE;
        case 'n':
            expect("null");
            return null;
        default:
            if (c == '-' || (c >= '0' && c <= '9'))
                return parseNumber();
            throw error("Unexpected character '" + c + "'");
        }
    }

    private Map<String, Object> parseObjectValue(int depth) throws IOException {
        Map<String, Object> map = new java.util.LinkedHashMap<String, Object>();
        pos++; // '{'
        skipWhitespace();
        if (peek() == '}') {
            pos++;
            return map;
        }
        for (;;) {
            skipWhitespace();
            if (peek() != '"')
                throw error("Expected object member name");
            String name = parseString();
            skipWhitespace();
            expectChar(':');
            skipWhitespace();
            map.put(name, parseValue(depth + 1));
            skipWhitespace();
            char c = peek();
            pos++;
            if (c == '}')
                return map;
            if (c != ',')
                throw error("Expected ',' or '}'");
        }
    }

    private Object[] parseArray(int depth) throws IOException {
        java.util.List<Object> list = new java.util.ArrayList<Object>();
        pos++; // '['
        skipWhitespace();
        if (peek() == ']') {
            pos++;
            return list.toArray();
        }
        for (;;) {
            skipWhitespace();
            list.add(parseValue(depth + 1));
            skipWhitespace();
            char c = peek();
            pos++;
            if (c == ']')
                return list.toArray();
            if (c != ',')
                throw error("Expected ',' or ']'");
        }
    }

    private String parseString() throws IOException {
        pos++; // opening quote
        StringBuilder sb = new StringBuilder();
        for (;;) {
            if (pos >= s.length())
                throw error("Unterminated string");
            char c = s.charAt(pos++);
            if (c == '"')
                return sb.toString();
            if (c != '\\') {
                sb.append(c);
                continue;
            }
            if (pos >= s.length())
                throw error("Unterminated escape sequence");
            char e = s.charAt(pos++);
            switch (e) {
            case '"':
            case '\\':
            case '/':
                sb.append(e);
                break;
            case 'b':
                sb.append('\b');
                break;
            case 'f':
                sb.append('\f');
                break;
            case 'n':
                sb.append('\n');
                break;
            case 'r':
                sb.append('\r');
                break;
            case 't':
                sb.append('\t');
                break;
            case 'u':
                if (pos + 4 > s.length())
                    throw error("Unterminated unicode escape");
                try {
                    sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                } catch (NumberFormatException ex) {
                    throw error("Invalid unicode escape");
                }
                pos += 4;
                break;
            default:
                throw error("Invalid escape character '" + e + "'");
            }
        }
    }

    private Object parseNumber() {
        int start = pos;
        if (peek() == '-')
            pos++;
        boolean integral = true;
        while (pos < s.length()) {
            char c = s.charAt(pos);
            if (c >= '0' && c <= '9') {
                pos++;
            } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                integral = false;
                pos++;
            } else {
                break;
            }
        }
        String number = s.substring(start, pos);
        try {
            return integral ? (Object) Long.valueOf(number) : (Object) Double.valueOf(number);
        } catch (NumberFormatException e) {
            return Double.valueOf(number);
        }
    }

    private void expect(String literal) throws IOException {
        if (!s.startsWith(literal, pos))
            throw error("Expected '" + literal + "'");
        pos += literal.length();
    }

    private void expectChar(char c) throws IOException {
        if (peek() != c)
            throw error("Expected '" + c + "'");
        pos++;
    }

    private char peek() throws IOException {
        if (pos >= s.length())
            throw error("Unexpected end of document");
        return s.charAt(pos);
    }

    private void skipWhitespace() {
        while (pos < s.length()) {
            char c = s.charAt(pos);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
                pos++;
            else
                break;
        }
    }

    private IOException error(String message) {
        return new IOException(message + " at position " + pos);
    }

    /**
     * Escapes a string so that it can be embedded in a JSON document.
     */
    public static String quote(String value) {
        if (value == null)
            return "null";
        StringBuilder sb = new StringBuilder(value.length() + 2);
        sb.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
            case '"':
                sb.append("\\\"");
                break;
            case '\\':
                sb.append("\\\\");
                break;
            case '\n':
                sb.append("\\n");
                break;
            case '\r':
                sb.append("\\r");
                break;
            case '\t':
                sb.append("\\t");
                break;
            case '\b':
                sb.append("\\b");
                break;
            case '\f':
                sb.append("\\f");
                break;
            default:
                if (c < 0x20)
                    sb.append(String.format("\\u%04x", (int) c));
                else
                    sb.append(c);
            }
        }
        return sb.append('"').toString();
    }

    /**
     * Serializes a map of scalars (or nested maps and arrays) to JSON.
     */
    public static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        write(value, sb);
        return sb.toString();
    }

    private static void write(Object value, StringBuilder sb) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof Map) {
            sb.append('{');
            Iterator<? extends Map.Entry<?, ?>> it = ((Map<?, ?>) value).entrySet().iterator();
            boolean first = true;
            while (it.hasNext()) {
                Map.Entry<?, ?> entry = it.next();
                if (!first)
                    sb.append(',');
                first = false;
                sb.append(quote(String.valueOf(entry.getKey()))).append(':');
                write(entry.getValue(), sb);
            }
            sb.append('}');
        } else if (value instanceof Object[]) {
            sb.append('[');
            Object[] array = (Object[]) value;
            for (int i = 0; i < array.length; i++) {
                if (i > 0)
                    sb.append(',');
                write(array[i], sb);
            }
            sb.append(']');
        } else if (value instanceof Number || value instanceof Boolean) {
            sb.append(value);
        } else {
            sb.append(quote(value.toString()));
        }
    }

    /**
     * Performs an HTTP request and returns the response body; a status outside
     * of the 2xx range is reported as {@link HttpStatusException}.
     */
    public static String readResponse(HttpURLConnection conn) throws IOException {
        int status = conn.getResponseCode();
        InputStream in = status >= 400 ? conn.getErrorStream() : conn.getInputStream();
        String body = in != null ? readFully(in) : "";
        if (status < 200 || status >= 300)
            throw new HttpStatusException(status, body);
        return body;
    }

    /**
     * Reads a stream completely, as UTF-8.
     */
    public static String readFully(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        copy(in, out);
        return new String(out.toByteArray(), UTF_8);
    }

    private static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0)
            out.write(buf, 0, n);
    }

    /**
     * Returns the URL with the UTF-8 character set encoding of a query string.
     */
    public static String encodeForm(Map<String, String> params) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (entry.getValue() == null)
                continue;
            if (sb.length() > 0)
                sb.append('&');
            sb.append(BffConfiguration.urlEncode(entry.getKey()))
              .append('=')
              .append(BffConfiguration.urlEncode(entry.getValue()));
        }
        return sb.toString();
    }

    public static byte[] utf8(String value) {
        return value.getBytes(UTF_8);
    }

    /**
     * Signals an unexpected HTTP status code returned by the OpenID Connect provider.
     */
    public static class HttpStatusException extends IOException {

        private static final long serialVersionUID = 1L;

        private final int status;
        private final String body;

        public HttpStatusException(int status, String body) {
            super("Unexpected HTTP status " + status + (body == null || body.isEmpty() ? "" : ": " + body));
            this.status = status;
            this.body = body;
        }

        public int getStatus() {
            return status;
        }

        public String getBody() {
            return body;
        }
    }
}
