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
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Validates the ID token received from the provider.
 * <p>
 * The BFF receives the ID token from the token endpoint, over a back channel that
 * is authenticated with the client credentials, so the token itself does not have
 * to be passed around. Nevertheless the claims that the BFF relies on are
 * validated: the issuer, the audience, the expiry, the issued-at time and the
 * nonce of the authorization request. Signature verification is intentionally left
 * to the resource servers (which get the access token) and would require the
 * provider's JWKS; the issuer and audience checks already prevent the token from
 * being replayed in another realm or client.
 *
 * @author dcm4che
 */
public class TokenValidator {

    /** Tolerance for clock skew between the BFF and the provider, in seconds. */
    public static final long DEFAULT_CLOCK_SKEW = 60;

    private final String issuer;
    private final String clientId;
    private final long clockSkew;

    public TokenValidator(BffConfiguration configuration, OpenIdClient.ProviderMetadata metadata) {
        this(metadata.getIssuer() != null ? metadata.getIssuer() : configuration.getIssuerUri(),
                configuration.getClientId(), DEFAULT_CLOCK_SKEW);
    }

    public TokenValidator(String issuer, String clientId, long clockSkew) {
        this.issuer = issuer;
        this.clientId = clientId;
        this.clockSkew = clockSkew;
    }

    /**
     * Validates the claims of an ID token.
     *
     * @param claims the claims of the ID token
     * @param expectedNonce the nonce of the authorization request, or <code>null</code> if none was sent
     * @param now the current time, in milliseconds since the epoch
     * @throws TokenValidationException if the token is not acceptable
     */
    public void validateIdToken(Map<String, Object> claims, String expectedNonce, long now)
            throws TokenValidationException {
        if (claims == null || claims.isEmpty())
            throw new TokenValidationException("Missing ID token claims");
        String sub = string(claims.get("sub"));
        if (sub == null || sub.isEmpty())
            throw new TokenValidationException("ID token without subject");

        String tokenIssuer = string(claims.get("iss"));
        if (tokenIssuer == null)
            throw new TokenValidationException("ID token without issuer");
        if (!sameIssuer(tokenIssuer, issuer))
            throw new TokenValidationException("Unexpected ID token issuer " + tokenIssuer);

        if (!audienceContains(claims.get("aud"), clientId))
            throw new TokenValidationException("ID token is not intended for client " + clientId);

        long nowSeconds = now / 1000L;
        long exp = number(claims.get("exp"));
        if (exp == 0)
            throw new TokenValidationException("ID token without expiration");
        if (nowSeconds - clockSkew >= exp)
            throw new TokenValidationException("ID token expired at " + exp);

        long iat = number(claims.get("iat"));
        if (iat != 0 && iat > nowSeconds + clockSkew)
            throw new TokenValidationException("ID token issued in the future: " + iat);

        Object nbf = claims.get("nbf");
        if (nbf != null && number(nbf) > nowSeconds + clockSkew)
            throw new TokenValidationException("ID token not valid yet: " + nbf);

        if (expectedNonce != null) {
            String nonce = string(claims.get("nonce"));
            if (!equalsConstantTime(expectedNonce, nonce))
                throw new TokenValidationException("ID token nonce does not match the authorization request");
        }

        String azp = string(claims.get("azp"));
        if (azp != null && !azp.equals(clientId))
            throw new TokenValidationException("ID token authorized party " + azp
                    + " is not the client " + clientId);
    }

    /**
     * Validates an access token used for a request forwarded to the backend: it
     * must be a JWT issued by the provider for this client, and must not be expired.
     */
    public Map<String, Object> validateAccessToken(String accessToken, long now)
            throws TokenValidationException {
        Map<String, Object> claims;
        try {
            claims = TokenSet.parseClaims(accessToken);
        } catch (IOException e) {
            throw new TokenValidationException("Malformed access token: " + e.getMessage());
        }
        long nowSeconds = now / 1000L;
        long exp = number(claims.get("exp"));
        if (exp != 0 && nowSeconds - clockSkew >= exp)
            throw new TokenValidationException("Access token expired at " + exp);
        String tokenIssuer = string(claims.get("iss"));
        if (tokenIssuer != null && !sameIssuer(tokenIssuer, issuer))
            throw new TokenValidationException("Unexpected access token issuer " + tokenIssuer);
        return claims;
    }

    /**
     * Compares two strings in constant time, to avoid leaking the expected value
     * through timing.
     */
    static boolean equalsConstantTime(String expected, String actual) {
        if (expected == null || actual == null)
            return false;
        try {
            return MessageDigest.isEqual(expected.getBytes("UTF-8"), actual.getBytes("UTF-8"));
        } catch (java.io.UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static boolean sameIssuer(String tokenIssuer, String configuredIssuer) {
        if (configuredIssuer == null)
            return true;
        return trimSlash(tokenIssuer).equalsIgnoreCase(trimSlash(configuredIssuer));
    }

    private static String trimSlash(String value) {
        String s = value.trim();
        while (s.endsWith("/"))
            s = s.substring(0, s.length() - 1);
        return s;
    }

    private static boolean audienceContains(Object aud, String clientId) {
        if (aud instanceof Object[]) {
            for (Object value : (Object[]) aud)
                if (clientId.equals(string(value)))
                    return true;
            return false;
        }
        return clientId.equals(string(aud));
    }

    private static long number(Object value) {
        if (value instanceof Number)
            return ((Number) value).longValue();
        if (value == null)
            return 0;
        try {
            return Long.parseLong(value.toString());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static String string(Object value) {
        return value != null ? value.toString() : null;
    }

    /**
     * Returns the claims of an ID token as a map suitable for a JSON response to
     * the frontend: only the claims that the frontend is allowed to see.
     */
    public static Map<String, Object> userInfo(TokenSet tokens) {
        Map<String, Object> info = new LinkedHashMap<String, Object>();
        if (tokens == null)
            return info;
        Map<String, Object> claims = tokens.getClaims();
        put(info, "sub", claims.get("sub"));
        put(info, "preferred_username", claims.get("preferred_username"));
        put(info, "name", claims.get("name"));
        put(info, "given_name", claims.get("given_name"));
        put(info, "family_name", claims.get("family_name"));
        put(info, "email", claims.get("email"));
        put(info, "email_verified", claims.get("email_verified"));
        put(info, "roles", tokens.getRoles().toArray());
        return info;
    }

    private static void put(Map<String, Object> map, String key, Object value) {
        if (value != null)
            map.put(key, value);
    }

    /**
     * Signals an ID token or access token that cannot be trusted.
     */
    public static class TokenValidationException extends Exception {

        private static final long serialVersionUID = 1L;

        public TokenValidationException(String message) {
            super(message);
        }
    }

    @Override
    public String toString() {
        return "TokenValidator[issuer=" + issuer + ", clientId=" + clientId
                + ", clockSkew=" + clockSkew + ", audience=" + Arrays.asList(clientId) + "]";
    }
}
