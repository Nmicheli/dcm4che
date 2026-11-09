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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Value object of an OpenID Connect token endpoint response, together with the
 * claims of the ID token.
 * <p>
 * A BFF keeps these tokens on the server; only the ID of the session is handed to
 * the browser, inside a HttpOnly cookie.
 *
 * @author dcm4che
 */
public class TokenSet {

    private static final char[] BASE64URL =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toCharArray();

    private final String accessToken;
    private final String refreshToken;
    private final String idToken;
    private final String tokenType;
    private final String scope;
    private final long expiresAt;
    private final Map<String, Object> claims;

    public TokenSet(String accessToken, String refreshToken, String idToken, String tokenType,
            String scope, long expiresAt, Map<String, Object> claims) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.idToken = idToken;
        this.tokenType = tokenType != null ? tokenType : "Bearer";
        this.scope = scope;
        this.expiresAt = expiresAt;
        this.claims = claims != null ? Collections.unmodifiableMap(claims) : Collections.<String, Object> emptyMap();
    }

    /**
     * Creates a token set from the response of the token endpoint.
     *
     * @param response the parsed token endpoint response
     * @param now the current time, in milliseconds since the epoch
     */
    public static TokenSet fromTokenResponse(Map<String, Object> response, long now) throws IOException {
        String accessToken = string(response.get("access_token"));
        if (accessToken == null)
            throw new IOException("Token response without access_token");
        String idToken = string(response.get("id_token"));
        long expiresIn = 0;
        Object exp = response.get("expires_in");
        if (exp instanceof Number)
            expiresIn = ((Number) exp).longValue() * 1000L;
        return new TokenSet(accessToken,
                string(response.get("refresh_token")),
                idToken,
                string(response.get("token_type")),
                string(response.get("scope")),
                expiresIn > 0 ? now + expiresIn : 0,
                idToken != null ? parseClaims(idToken) : null);
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public String getIdToken() {
        return idToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public String getScope() {
        return scope;
    }

    /**
     * Returns the expiration instant of the access token, in milliseconds since
     * the epoch, or <code>0</code> if the provider did not report it.
     */
    public long getExpiresAt() {
        return expiresAt;
    }

    public Map<String, Object> getClaims() {
        return claims;
    }

    public String getSubject() {
        return string(claims.get("sub"));
    }

    public String getPreferredUsername() {
        return string(claims.get("preferred_username"));
    }

    public String getEmail() {
        return string(claims.get("email"));
    }

    public String getName() {
        return string(claims.get("name"));
    }

    /**
     * Returns the roles granted by Keycloak, taken from
     * <code>realm_access.roles</code> and from
     * <code>resource_access.&lt;client-id&gt;.roles</code>.
     */
    public List<String> getRoles() {
        List<String> roles = new ArrayList<String>();
        addRoles(roles, claims.get("realm_access"));
        Object resourceAccess = claims.get("resource_access");
        if (resourceAccess instanceof Map)
            for (Object client : ((Map<?, ?>) resourceAccess).values())
                addRoles(roles, client);
        return Collections.unmodifiableList(roles);
    }

    public boolean isExpired(long now) {
        return expiresAt > 0 && now >= expiresAt;
    }

    /**
     * Returns the remaining validity of the access token, in seconds; a negative
     * value means that the token is already expired, <code>-1</code> that the
     * validity is unknown.
     */
    public long getExpiresIn(long now) {
        return expiresAt > 0 ? (expiresAt - now) / 1000L : -1;
    }

    @SuppressWarnings("unchecked")
    private static void addRoles(List<String> roles, Object container) {
        if (!(container instanceof Map))
            return;
        Object value = ((Map<String, Object>) container).get("roles");
        if (!(value instanceof Object[]))
            return;
        for (Object role : (Object[]) value)
            if (role != null && !roles.contains(role.toString()))
                roles.add(role.toString());
    }

    /**
     * Extracts the claims of a JSON Web Token, without verifying its signature.
     * Callers must not trust these claims unless the token was received over a
     * trusted channel (the token endpoint of the provider) or verified otherwise.
     */
    public static Map<String, Object> parseClaims(String jwt) throws IOException {
        String[] parts = jwt.split("\\.");
        if (parts.length < 2)
            throw new IOException("Malformed JSON Web Token");
        return Json.parseObject(new String(base64UrlDecode(parts[1]), "UTF-8"));
    }

    /**
     * Generates a cryptographically strong random value, Base64 URL encoded
     * without padding; used for the OAuth 2.0 state and PKCE code verifier.
     */
    public static String randomToken(int numBytes) {
        byte[] bytes = new byte[numBytes];
        new SecureRandom().nextBytes(bytes);
        return base64UrlEncode(bytes);
    }

    /**
     * Returns the PKCE code challenge (S256) for the given code verifier.
     */
    public static String codeChallenge(String verifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return base64UrlEncode(digest.digest(verifier.getBytes("US-ASCII")));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String base64UrlEncode(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        for (; i + 2 < bytes.length; i += 3) {
            int b = ((bytes[i] & 0xff) << 16) | ((bytes[i + 1] & 0xff) << 8) | (bytes[i + 2] & 0xff);
            sb.append(BASE64URL[(b >> 18) & 0x3f]);
            sb.append(BASE64URL[(b >> 12) & 0x3f]);
            sb.append(BASE64URL[(b >> 6) & 0x3f]);
            sb.append(BASE64URL[b & 0x3f]);
        }
        int remaining = bytes.length - i;
        if (remaining == 1) {
            int b = (bytes[i] & 0xff) << 16;
            sb.append(BASE64URL[(b >> 18) & 0x3f]);
            sb.append(BASE64URL[(b >> 12) & 0x3f]);
        } else if (remaining == 2) {
            int b = ((bytes[i] & 0xff) << 16) | ((bytes[i + 1] & 0xff) << 8);
            sb.append(BASE64URL[(b >> 18) & 0x3f]);
            sb.append(BASE64URL[(b >> 12) & 0x3f]);
            sb.append(BASE64URL[(b >> 6) & 0x3f]);
        }
        return sb.toString();
    }

    public static byte[] base64UrlDecode(String value) throws IOException {
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '-')
                sb.append('+');
            else if (c == '_')
                sb.append('/');
            else if (c != '=')
                sb.append(c);
        }
        String s = sb.toString();
        int remainder = s.length() % 4;
        if (remainder == 1)
            throw new IOException("Malformed Base64 URL encoding");
        while (s.length() % 4 != 0)
            s += '=';
        return decode(s);
    }

    private static byte[] decode(String s) throws IOException {
        byte[] out = new byte[s.length() * 3 / 4];
        int o = 0;
        for (int i = 0; i < s.length(); i += 4) {
            int[] v = new int[4];
            int pad = 0;
            for (int j = 0; j < 4; j++) {
                char c = s.charAt(i + j);
                if (c == '=') {
                    v[j] = 0;
                    pad++;
                } else {
                    v[j] = decodeChar(c);
                }
            }
            int b = (v[0] << 18) | (v[1] << 12) | (v[2] << 6) | v[3];
            if (o < out.length)
                out[o++] = (byte) ((b >> 16) & 0xff);
            if (pad < 2 && o < out.length)
                out[o++] = (byte) ((b >> 8) & 0xff);
            if (pad < 1 && o < out.length)
                out[o++] = (byte) (b & 0xff);
        }
        byte[] result = new byte[o];
        System.arraycopy(out, 0, result, 0, o);
        return result;
    }

    private static int decodeChar(char c) throws IOException {
        if (c >= 'A' && c <= 'Z')
            return c - 'A';
        if (c >= 'a' && c <= 'z')
            return c - 'a' + 26;
        if (c >= '0' && c <= '9')
            return c - '0' + 52;
        if (c == '+')
            return 62;
        if (c == '/')
            return 63;
        throw new IOException("Invalid Base64 character '" + c + "'");
    }

    private static String string(Object value) {
        return value != null ? value.toString() : null;
    }

    @Override
    public String toString() {
        return "TokenSet[subject=" + getSubject() + ", scope=" + scope + ", expiresAt=" + expiresAt + "]";
    }
}
