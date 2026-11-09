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
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * OpenID Connect client of the BFF, talking to a Keycloak realm.
 * <p>
 * The client implements the Authorization Code flow with PKCE and performs the
 * back channel calls (discovery, token, refresh, revocation, logout) on behalf of
 * the frontend. The tokens never leave the server.
 *
 * @author dcm4che
 */
public class OpenIdClient {

    private static final Logger LOG = LoggerFactory.getLogger(OpenIdClient.class);

    private final BffConfiguration configuration;
    private final ProviderMetadata metadata;

    public OpenIdClient(BffConfiguration configuration, ProviderMetadata metadata) {
        this.configuration = configuration;
        this.metadata = metadata;
    }

    /**
     * Loads the provider metadata from the discovery document of the issuer.
     */
    public static ProviderMetadata discover(BffConfiguration configuration) throws IOException {
        return ProviderMetadata.fetch(configuration.getDiscoveryUri());
    }

    /**
     * Creates a client, loading the provider metadata from the discovery document.
     */
    public static OpenIdClient create(BffConfiguration configuration) throws IOException {
        return new OpenIdClient(configuration, discover(configuration));
    }

    public BffConfiguration getConfiguration() {
        return configuration;
    }

    public ProviderMetadata getMetadata() {
        return metadata;
    }

    /**
     * Returns the authorization endpoint URL the browser has to be redirected to.
     *
     * @param state the OAuth 2.0 state, bound to the browser session
     * @param codeChallenge the PKCE code challenge (S256) of the session's code verifier
     * @param nonce the OpenID Connect nonce, to bind the ID token to this request
     */
    public String getAuthorizationUrl(String state, String codeChallenge, String nonce) {
        return getAuthorizationUrl(state, codeChallenge, nonce, configuration.getRedirectUri());
    }

    public String getAuthorizationUrl(String state, String codeChallenge, String nonce, String redirectUri) {
        StringBuilder sb = new StringBuilder(metadata.getAuthorizationEndpoint());
        sb.append(metadata.getAuthorizationEndpoint().indexOf('?') >= 0 ? '&' : '?');
        sb.append("response_type=code")
          .append("&client_id=").append(BffConfiguration.urlEncode(configuration.getClientId()))
          .append("&redirect_uri=").append(BffConfiguration.urlEncode(redirectUri))
          .append("&scope=").append(BffConfiguration.urlEncode(configuration.getScope()))
          .append("&state=").append(BffConfiguration.urlEncode(state));
        if (codeChallenge != null)
            sb.append("&code_challenge=").append(BffConfiguration.urlEncode(codeChallenge))
              .append("&code_challenge_method=S256");
        if (nonce != null)
            sb.append("&nonce=").append(BffConfiguration.urlEncode(nonce));
        return sb.toString();
    }

    /**
     * Exchanges an authorization code for a token set.
     */
    public TokenSet exchangeCode(String code, String codeVerifier) throws IOException {
        Map<String, String> form = new LinkedHashMap<String, String>();
        form.put("grant_type", "authorization_code");
        form.put("code", code);
        form.put("redirect_uri", configuration.getRedirectUri());
        if (codeVerifier != null)
            form.put("code_verifier", codeVerifier);
        return postTokenRequest(form);
    }

    /**
     * Refreshes a token set.
     */
    public TokenSet refresh(String refreshToken) throws IOException {
        Map<String, String> form = new LinkedHashMap<String, String>();
        form.put("grant_type", "refresh_token");
        form.put("refresh_token", refreshToken);
        return postTokenRequest(form);
    }

    /**
     * Revokes the refresh token at the provider, if it exposes a revocation endpoint.
     * Failures are logged, but not propagated: a logout must always succeed locally.
     */
    public void revoke(String token, String tokenTypeHint) {
        String endpoint = metadata.getRevocationEndpoint();
        if (endpoint == null || token == null)
            return;
        Map<String, String> form = new LinkedHashMap<String, String>();
        form.put("token", token);
        if (tokenTypeHint != null)
            form.put("token_type_hint", tokenTypeHint);
        try {
            post(endpoint, form);
        } catch (IOException e) {
            LOG.warn("Failed to revoke token at {}", endpoint, e);
        }
    }

    /**
     * Returns the URL of the end session endpoint, with the post logout redirect
     * URI, or <code>null</code> if the provider does not support RP initiated logout.
     */
    public String getLogoutUrl(String idToken) {
        String endpoint = metadata.getEndSessionEndpoint();
        if (endpoint == null)
            return null;
        StringBuilder sb = new StringBuilder(endpoint);
        sb.append(endpoint.indexOf('?') >= 0 ? '&' : '?');
        sb.append("client_id=").append(BffConfiguration.urlEncode(configuration.getClientId()));
        if (configuration.getPostLogoutRedirectUri() != null)
            sb.append("&post_logout_redirect_uri=")
              .append(BffConfiguration.urlEncode(configuration.getPostLogoutRedirectUri()));
        if (idToken != null)
            sb.append("&id_token_hint=").append(BffConfiguration.urlEncode(idToken));
        return sb.toString();
    }

    private TokenSet postTokenRequest(Map<String, String> form) throws IOException {
        form.put("client_id", configuration.getClientId());
        if (configuration.isConfidentialClient())
            form.put("client_secret", configuration.getClientSecret());
        String body = post(metadata.getTokenEndpoint(), form);
        return TokenSet.fromTokenResponse(Json.parseObject(body), System.currentTimeMillis());
    }

    /**
     * Posts a form encoded request and returns the response body.
     */
    protected String post(String endpoint, Map<String, String> form) throws IOException {
        byte[] payload = Json.utf8(Json.encodeForm(form));
        HttpURLConnection conn = (HttpURLConnection) new URL(endpoint).openConnection();
        try {
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(30000);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Accept", "application/json");
            conn.getOutputStream().write(payload);
            return Json.readResponse(conn);
        } finally {
            conn.disconnect();
        }
    }

    /**
     * The subset of the OpenID Connect discovery document used by the BFF.
     */
    public static class ProviderMetadata {

        private final String issuer;
        private final String authorizationEndpoint;
        private final String tokenEndpoint;
        private final String endSessionEndpoint;
        private final String revocationEndpoint;
        private final String jwksUri;

        public ProviderMetadata(String issuer, String authorizationEndpoint, String tokenEndpoint,
                String endSessionEndpoint, String revocationEndpoint, String jwksUri) {
            this.issuer = issuer;
            this.authorizationEndpoint = require(authorizationEndpoint, "authorization_endpoint");
            this.tokenEndpoint = require(tokenEndpoint, "token_endpoint");
            this.endSessionEndpoint = endSessionEndpoint;
            this.revocationEndpoint = revocationEndpoint;
            this.jwksUri = jwksUri;
        }

        /**
         * Fetches and parses the discovery document.
         */
        public static ProviderMetadata fetch(String discoveryUri) throws IOException {
            HttpURLConnection conn = (HttpURLConnection) new URL(discoveryUri).openConnection();
            try {
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(10000);
                conn.setReadTimeout(30000);
                conn.setRequestProperty("Accept", "application/json");
                return fromDiscovery(Json.parseObject(Json.readResponse(conn)));
            } finally {
                conn.disconnect();
            }
        }

        public static ProviderMetadata fromDiscovery(Map<String, Object> doc) throws IOException {
            return new ProviderMetadata(
                    string(doc.get("issuer")),
                    string(doc.get("authorization_endpoint")),
                    string(doc.get("token_endpoint")),
                    string(doc.get("end_session_endpoint")),
                    string(doc.get("revocation_endpoint")),
                    string(doc.get("jwks_uri")));
        }

        private static String require(String value, String name) {
            if (value == null || value.isEmpty())
                throw new IllegalArgumentException("Discovery document without " + name);
            return value;
        }

        private static String string(Object value) {
            return value != null ? value.toString() : null;
        }

        public String getIssuer() {
            return issuer;
        }

        public String getAuthorizationEndpoint() {
            return authorizationEndpoint;
        }

        public String getTokenEndpoint() {
            return tokenEndpoint;
        }

        public String getEndSessionEndpoint() {
            return endSessionEndpoint;
        }

        public String getRevocationEndpoint() {
            return revocationEndpoint;
        }

        public String getJwksUri() {
            return jwksUri;
        }
    }
}
