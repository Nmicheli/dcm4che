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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.Map;

import org.junit.Test;

/**
 * Tests the validation of ID and access tokens.
 */
public class TokenValidatorTest {

    private static final String ISSUER = "https://keycloak.example.com/realms/dcm4che";
    private static final String CLIENT_ID = "dcm4che-bff";
    private static final long NOW = 1700000000000L;
    private static final long NOW_SECONDS = NOW / 1000L;

    private final TokenValidator validator = new TokenValidator(ISSUER, CLIENT_ID, 60);

    @Test
    public void testValidIdToken() throws Exception {
        validator.validateIdToken(claims("u1", ISSUER, "\"" + CLIENT_ID + "\"", NOW_SECONDS + 300,
                NOW_SECONDS, "nonce-1", null), "nonce-1", NOW);
    }

    @Test
    public void testValidIdTokenWithoutNonceCheck() throws Exception {
        validator.validateIdToken(claims("u1", ISSUER, "\"" + CLIENT_ID + "\"", NOW_SECONDS + 300,
                NOW_SECONDS, null, null), null, NOW);
    }

    @Test
    public void testIssuerWithTrailingSlashIsAccepted() throws Exception {
        validator.validateIdToken(claims("u1", ISSUER + "/", "\"" + CLIENT_ID + "\"", NOW_SECONDS + 300,
                NOW_SECONDS, null, null), null, NOW);
    }

    @Test
    public void testAudienceAsArray() throws Exception {
        validator.validateIdToken(claims("u1", ISSUER, "[\"other-client\",\"" + CLIENT_ID + "\"]",
                NOW_SECONDS + 300, NOW_SECONDS, null, null), null, NOW);
    }

    @Test
    public void testWrongIssuerIsRejected() {
        assertRejected(claims("u1", "https://evil.example.com/realms/dcm4che", "\"" + CLIENT_ID + "\"",
                NOW_SECONDS + 300, NOW_SECONDS, null, null), null, "issuer");
    }

    @Test
    public void testWrongAudienceIsRejected() {
        assertRejected(claims("u1", ISSUER, "\"another-client\"", NOW_SECONDS + 300, NOW_SECONDS, null, null),
                null, "client");
    }

    @Test
    public void testExpiredIdTokenIsRejected() {
        assertRejected(claims("u1", ISSUER, "\"" + CLIENT_ID + "\"", NOW_SECONDS - 61, NOW_SECONDS - 400,
                null, null), null, "expired");
    }

    @Test
    public void testIdTokenWithinClockSkewIsAccepted() throws Exception {
        validator.validateIdToken(claims("u1", ISSUER, "\"" + CLIENT_ID + "\"", NOW_SECONDS - 30,
                NOW_SECONDS - 400, null, null), null, NOW);
    }

    @Test
    public void testIdTokenIssuedInTheFutureIsRejected() {
        assertRejected(claims("u1", ISSUER, "\"" + CLIENT_ID + "\"", NOW_SECONDS + 600,
                NOW_SECONDS + 300, null, null), null, "future");
    }

    @Test
    public void testNotBeforeInTheFutureIsRejected() {
        String json = "{\"sub\":\"u1\",\"iss\":\"" + ISSUER + "\",\"aud\":\"" + CLIENT_ID + "\","
                + "\"exp\":" + (NOW_SECONDS + 300) + ",\"iat\":" + NOW_SECONDS + ","
                + "\"nbf\":" + (NOW_SECONDS + 300) + "}";
        assertRejected(json, null, "not valid yet");
    }

    @Test
    public void testNonceMismatchIsRejected() {
        assertRejected(claims("u1", ISSUER, "\"" + CLIENT_ID + "\"", NOW_SECONDS + 300, NOW_SECONDS,
                "nonce-1", null), "nonce-2", "nonce");
    }

    @Test
    public void testMissingNonceIsRejected() {
        assertRejected(claims("u1", ISSUER, "\"" + CLIENT_ID + "\"", NOW_SECONDS + 300, NOW_SECONDS,
                null, null), "nonce-1", "nonce");
    }

    @Test
    public void testAuthorizedPartyMustMatchClient() {
        assertRejected(claims("u1", ISSUER, "\"" + CLIENT_ID + "\"", NOW_SECONDS + 300, NOW_SECONDS,
                null, "another-client"), null, "authorized party");
    }

    @Test
    public void testMissingSubjectIsRejected() {
        assertRejected("{\"iss\":\"" + ISSUER + "\",\"aud\":\"" + CLIENT_ID + "\",\"exp\":"
                + (NOW_SECONDS + 300) + "}", null, "subject");
    }

    @Test
    public void testMissingExpirationIsRejected() {
        assertRejected("{\"sub\":\"u1\",\"iss\":\"" + ISSUER + "\",\"aud\":\"" + CLIENT_ID + "\"}", null,
                "expiration");
    }

    @Test
    public void testEmptyClaimsAreRejected() {
        assertRejected("{}", null, "claims");
        try {
            validator.validateIdToken(null, null, NOW);
            fail("Null claims must be rejected");
        } catch (TokenValidator.TokenValidationException expected) {
            // expected
        }
    }

    @Test
    public void testAccessTokenValidation() throws Exception {
        String jwt = jwt("{\"sub\":\"u1\",\"iss\":\"" + ISSUER + "\",\"exp\":" + (NOW_SECONDS + 300) + "}");
        Map<String, Object> claims = validator.validateAccessToken(jwt, NOW);
        assertEquals("u1", claims.get("sub"));
    }

    @Test
    public void testExpiredAccessTokenIsRejected() {
        String jwt = jwt("{\"sub\":\"u1\",\"iss\":\"" + ISSUER + "\",\"exp\":" + (NOW_SECONDS - 61) + "}");
        try {
            validator.validateAccessToken(jwt, NOW);
            fail("Expired access token must be rejected");
        } catch (TokenValidator.TokenValidationException e) {
            assertTrue(e.getMessage().contains("expired"));
        }
    }

    @Test
    public void testAccessTokenOfAnotherIssuerIsRejected() {
        String jwt = jwt("{\"sub\":\"u1\",\"iss\":\"https://other.example.com\",\"exp\":"
                + (NOW_SECONDS + 300) + "}");
        try {
            validator.validateAccessToken(jwt, NOW);
            fail("Access token of another issuer must be rejected");
        } catch (TokenValidator.TokenValidationException e) {
            assertTrue(e.getMessage().contains("issuer"));
        }
    }

    @Test
    public void testMalformedAccessTokenIsRejected() {
        try {
            validator.validateAccessToken("garbage", NOW);
            fail("Malformed access token must be rejected");
        } catch (TokenValidator.TokenValidationException e) {
            assertTrue(e.getMessage().contains("Malformed"));
        }
    }

    @Test
    public void testConstantTimeComparison() {
        assertTrue(TokenValidator.equalsConstantTime("abc", "abc"));
        assertFalse(TokenValidator.equalsConstantTime("abc", "abd"));
        assertFalse(TokenValidator.equalsConstantTime("abc", null));
        assertFalse(TokenValidator.equalsConstantTime(null, "abc"));
    }

    @Test
    public void testProviderMetadataRequiresEndpoints() {
        try {
            OpenIdClient.ProviderMetadata.fromDiscovery(Json.parseObject(
                    "{\"issuer\":\"" + ISSUER + "\",\"token_endpoint\":\"https://kc/token\"}"));
            fail("Discovery without authorization endpoint must be rejected");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("authorization_endpoint"));
        } catch (IOException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testProviderMetadataOptionalEndpoints() throws IOException {
        OpenIdClient.ProviderMetadata metadata = OpenIdClient.ProviderMetadata.fromDiscovery(Json.parseObject(
                "{\"issuer\":\"" + ISSUER + "\","
                + "\"authorization_endpoint\":\"https://kc/auth\","
                + "\"token_endpoint\":\"https://kc/token\"}"));
        assertNotNull(metadata.getAuthorizationEndpoint());
        assertEquals("https://kc/token", metadata.getTokenEndpoint());
        assertNull(metadata.getEndSessionEndpoint());
        assertNull(metadata.getRevocationEndpoint());
    }

    private void assertRejected(String claimsJson, String nonce, String expectedMessagePart) {
        try {
            assertRejected(Json.parseObject(claimsJson), nonce, expectedMessagePart);
        } catch (IOException e) {
            fail(e.getMessage());
        }
    }

    private void assertRejected(Map<String, Object> claims, String nonce, String expectedMessagePart) {
        try {
            validator.validateIdToken(claims, nonce, NOW);
            fail("Expected rejection of " + claims);
        } catch (TokenValidator.TokenValidationException e) {
            assertTrue("unexpected message: " + e.getMessage(),
                    e.getMessage().toLowerCase().contains(expectedMessagePart.toLowerCase()));
        }
    }

    private static Map<String, Object> claims(String sub, String iss, String aud, long exp, long iat, String nonce,
            String azp) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"sub\":\"").append(sub).append("\",");
        sb.append("\"iss\":\"").append(iss).append("\",");
        sb.append("\"aud\":").append(aud).append(',');
        sb.append("\"exp\":").append(exp).append(',');
        sb.append("\"iat\":").append(iat);
        if (nonce != null)
            sb.append(",\"nonce\":\"").append(nonce).append('"');
        if (azp != null)
            sb.append(",\"azp\":\"").append(azp).append('"');
        try {
            return Json.parseObject(sb.append('}').toString());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String jwt(String claimsJson) {
        return "eyJhbGciOiJSUzI1NiJ9." + TokenSet.base64UrlEncode(Json.utf8(claimsJson)) + ".signature";
    }
}
