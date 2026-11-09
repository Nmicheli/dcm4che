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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.junit.Test;

/**
 * Tests the JSON handling, the JWT decoding and the PKCE helpers.
 */
public class JsonAndTokenTest {

    @Test
    public void testParseNestedDocument() throws IOException {
        Map<String, Object> doc = Json.parseObject("{ \"issuer\": \"https://kc/realms/dcm4che\","
                + " \"end_session_endpoint\": \"https://kc/logout\","
                + " \"grant_types_supported\": [\"authorization_code\", \"refresh_token\"],"
                + " \"flags\": {\"pkce\": true, \"id_token_signing\": null},"
                + " \"expires_in\": 300, \"ratio\": 1.5 }");
        assertEquals("https://kc/realms/dcm4che", doc.get("issuer"));
        assertEquals(2, ((Object[]) doc.get("grant_types_supported")).length);
        assertEquals(Long.valueOf(300), doc.get("expires_in"));
        assertEquals(Double.valueOf(1.5), doc.get("ratio"));
        Map<?, ?> flags = (Map<?, ?>) doc.get("flags");
        assertEquals(Boolean.TRUE, flags.get("pkce"));
        assertTrue(flags.containsKey("id_token_signing"));
        assertNull(flags.get("id_token_signing"));
    }

    @Test
    public void testEscapes() throws IOException {
        Map<String, Object> doc = Json.parseObject("{\"a\":\"line\\nbreak\\t\\\"quoted\\\" \\u00e8\", \"b\":\"\"}");
        assertEquals("line\nbreak\t\"quoted\" \u00e8", doc.get("a"));
        assertEquals("", doc.get("b"));
    }

    @Test
    public void testInvalidDocumentsAreRejected() {
        assertMalformed("{");
        assertMalformed("{\"a\":}");
        assertMalformed("{\"a\":1} trailing");
        assertMalformed("[\"unterminated]");
        assertMalformed("{\"a\":01x}");
        assertMalformed("");
        assertMalformed("{\"a\":\"\\q\"}");
    }

    @Test
    public void testObjectIsRequired() {
        try {
            Json.parseObject("[]");
            fail("An array is not an object");
        } catch (IOException e) {
            assertTrue(e.getMessage().contains("object"));
        }
    }

    @Test
    public void testQuoteAndWrite() throws IOException {
        assertEquals("\"a\\\"b\\\\c\\n\"", Json.quote("a\"b\\c\n"));
        assertEquals("null", Json.quote(null));
        assertEquals("{\"k\":\"v\",\"n\":1,\"b\":true,\"x\":null}",
                Json.write(Json.parseObject("{\"k\":\"v\",\"n\":1,\"b\":true,\"x\":null}")));
    }

    @Test
    public void testBase64UrlRoundTrip() throws IOException {
        byte[] bytes = new byte[] { 0, 1, 2, (byte) 0xff, (byte) 0xfe, 42, 7 };
        String encoded = TokenSet.base64UrlEncode(bytes);
        assertFalse(encoded.contains("="));
        assertFalse(encoded.contains("+"));
        assertFalse(encoded.contains("/"));
        assertArrayEquals(bytes, TokenSet.base64UrlDecode(encoded));
    }

    @Test
    public void testPkceChallengeMatchesRfc7636Example() {
        // test vector of RFC 7636, Appendix B
        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                TokenSet.codeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
    }

    @Test
    public void testRandomTokensAreUnique() {
        String a = TokenSet.randomToken(32);
        String b = TokenSet.randomToken(32);
        assertFalse(a.equals(b));
        assertEquals(43, a.length()); // 32 bytes, Base64 URL without padding
    }

    @Test
    public void testParseClaimsOfUnsignedJwt() throws IOException {
        String payload = TokenSet.base64UrlEncode(Json.utf8(
                "{\"sub\":\"8a8b\",\"iss\":\"https://kc/realms/dcm4che\",\"aud\":\"dcm4che-bff\"}"));
        Map<String, Object> claims = TokenSet.parseClaims("eyJhbGciOiJub25lIn0." + payload + ".sig");
        assertEquals("8a8b", claims.get("sub"));
        assertEquals("dcm4che-bff", claims.get("aud"));
    }

    @Test
    public void testMalformedJwtIsRejected() {
        try {
            TokenSet.parseClaims("not-a-jwt");
            fail("Malformed token must be rejected");
        } catch (IOException e) {
            assertTrue(e.getMessage().contains("Malformed"));
        }
    }

    @Test
    public void testKeycloakRoles() {
        TokenSet tokens = tokens("{\"sub\":\"u1\","
                + "\"realm_access\":{\"roles\":[\"dcm4che-user\",\"offline_access\"]},"
                + "\"resource_access\":{\"dcm4che-bff\":{\"roles\":[\"admin\"]},"
                + "\"other-client\":{\"roles\":[\"admin\",\"reader\"]}}}");
        List<String> roles = tokens.getRoles();
        assertEquals(4, roles.size());
        assertTrue(roles.contains("dcm4che-user"));
        assertTrue(roles.contains("offline_access"));
        assertTrue(roles.contains("admin"));
        assertTrue(roles.contains("reader"));
    }

    @Test
    public void testTokenSetFromTokenResponse() throws IOException {
        long now = 1700000000000L;
        Map<String, Object> response = Json.parseObject("{\"access_token\":\"at\",\"refresh_token\":\"rt\","
                + "\"expires_in\":300,\"token_type\":\"Bearer\",\"scope\":\"openid profile\","
                + "\"id_token\":\"header." + TokenSet.base64UrlEncode(Json.utf8("{\"sub\":\"u1\",\"nonce\":\"n1\"}"))
                + ".signature\"}");
        TokenSet tokens = TokenSet.fromTokenResponse(response, now);
        assertEquals("at", tokens.getAccessToken());
        assertEquals("rt", tokens.getRefreshToken());
        assertEquals(now + 300000L, tokens.getExpiresAt());
        assertEquals("Bearer", tokens.getTokenType());
        assertEquals("u1", tokens.getSubject());
        assertEquals("n1", tokens.getClaims().get("nonce"));
        assertEquals(300, tokens.getExpiresIn(now));
        assertFalse(tokens.isExpired(now));
        assertTrue(tokens.isExpired(now + 300000L));
    }

    @Test
    public void testTokenResponseWithoutAccessTokenIsRejected() {
        try {
            TokenSet.fromTokenResponse(Json.parseObject("{\"id_token\":\"a.b.c\"}"), System.currentTimeMillis());
            fail("A token response without access token must be rejected");
        } catch (IOException e) {
            assertTrue(e.getMessage().contains("access_token"));
        }
    }

    @Test
    public void testUserInfoDoesNotLeakTokens() {
        TokenSet tokens = tokens("{\"sub\":\"u1\",\"preferred_username\":\"jdoe\",\"email\":\"j@example.com\","
                + "\"realm_access\":{\"roles\":[\"user\"]}}");
        Map<String, Object> info = TokenValidator.userInfo(tokens);
        assertEquals("u1", info.get("sub"));
        assertEquals("jdoe", info.get("preferred_username"));
        assertEquals("j@example.com", info.get("email"));
        assertFalse(info.containsKey("access_token"));
        assertFalse(info.containsKey("refresh_token"));
        assertTrue(TokenValidator.userInfo(null).isEmpty());
    }

    static TokenSet tokens(String claimsJson) {
        try {
            return new TokenSet("access", "refresh", "id", "Bearer", "openid",
                    System.currentTimeMillis() + 300000L, Json.parseObject(claimsJson));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void assertMalformed(String json) {
        try {
            Json.parse(json);
            fail("Expected malformed JSON to be rejected: " + json);
        } catch (IOException expected) {
            // expected
        }
    }
}
