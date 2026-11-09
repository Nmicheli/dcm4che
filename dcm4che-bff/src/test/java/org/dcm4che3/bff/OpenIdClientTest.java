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
import java.util.Properties;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests the OpenID Connect client against a fake provider: discovery, the
 * authorization request with PKCE, the code exchange, the refresh and the logout.
 */
public class OpenIdClientTest {

    private ServletStubs.FakeOpenIdProvider provider;
    private BffConfiguration configuration;

    @Before
    public void setUp() throws IOException {
        provider = new ServletStubs.FakeOpenIdProvider();
        Properties props = new Properties();
        props.setProperty(BffConfiguration.PROP_ISSUER_URI, provider.getIssuer());
        props.setProperty(BffConfiguration.PROP_CLIENT_ID, ServletStubs.FakeOpenIdProvider.CLIENT_ID);
        props.setProperty(BffConfiguration.PROP_CLIENT_SECRET, ServletStubs.FakeOpenIdProvider.CLIENT_SECRET);
        props.setProperty(BffConfiguration.PROP_REDIRECT_URI, "https://dcm4che.example.com/bff/callback");
        props.setProperty(BffConfiguration.PROP_POST_LOGOUT_REDIRECT_URI, "https://dcm4che.example.com/");
        configuration = BffConfiguration.fromProperties(props);
    }

    @After
    public void tearDown() {
        provider.stop();
    }

    @Test
    public void testDiscovery() throws IOException {
        OpenIdClient.ProviderMetadata metadata = OpenIdClient.discover(configuration);
        assertEquals(provider.getIssuer(), metadata.getIssuer());
        assertEquals(provider.getBaseUrl() + "/realms/dcm4che/protocol/openid-connect/auth",
                metadata.getAuthorizationEndpoint());
        assertEquals(provider.getBaseUrl() + "/realms/dcm4che/protocol/openid-connect/token",
                metadata.getTokenEndpoint());
        assertEquals(provider.getBaseUrl() + "/realms/dcm4che/protocol/openid-connect/logout",
                metadata.getEndSessionEndpoint());
        assertEquals(provider.getBaseUrl() + "/realms/dcm4che/protocol/openid-connect/revoke",
                metadata.getRevocationEndpoint());
    }

    @Test
    public void testDiscoveryOfUnknownIssuerFails() throws IOException {
        Properties props = new Properties();
        props.setProperty(BffConfiguration.PROP_ISSUER_URI, "http://127.0.0.1:1/realms/none");
        props.setProperty(BffConfiguration.PROP_CLIENT_ID, "x");
        props.setProperty(BffConfiguration.PROP_REDIRECT_URI, "https://example.com/cb");
        try {
            OpenIdClient.discover(BffConfiguration.fromProperties(props));
            fail("Discovery against a dead provider must fail");
        } catch (IOException expected) {
            // expected
        }
    }

    @Test
    public void testAuthorizationUrlContainsPkceStateAndNonce() throws IOException {
        OpenIdClient client = OpenIdClient.create(configuration);
        String url = client.getAuthorizationUrl("state-1", "challenge-1", "nonce-1");
        assertTrue(url.startsWith(provider.getBaseUrl() + "/realms/dcm4che/protocol/openid-connect/auth?"));
        assertTrue(url.contains("response_type=code"));
        assertTrue(url.contains("client_id=" + ServletStubs.FakeOpenIdProvider.CLIENT_ID));
        assertTrue(url.contains("redirect_uri=https%3A%2F%2Fdcm4che.example.com%2Fbff%2Fcallback"));
        assertTrue(url.contains("scope=openid+profile+email"));
        assertTrue(url.contains("state=state-1"));
        assertTrue(url.contains("code_challenge=challenge-1"));
        assertTrue(url.contains("code_challenge_method=S256"));
        assertTrue(url.contains("nonce=nonce-1"));
        assertFalse(url.contains(ServletStubs.FakeOpenIdProvider.CLIENT_SECRET));
    }

    @Test
    public void testAuthorizationUrlWithoutPkceOrNonce() throws IOException {
        OpenIdClient client = OpenIdClient.create(configuration);
        String url = client.getAuthorizationUrl("state-1", null, null);
        assertFalse(url.contains("code_challenge"));
        assertFalse(url.contains("nonce"));
    }

    @Test
    public void testExchangeCodeSendsVerifierAndSecret() throws IOException {
        OpenIdClient client = OpenIdClient.create(configuration);
        TokenSet tokens = client.exchangeCode(ServletStubs.FakeOpenIdProvider.CODE, "verifier-1");
        assertEquals(ServletStubs.FakeOpenIdProvider.SUBJECT, tokens.getSubject());
        assertEquals(ServletStubs.FakeOpenIdProvider.USERNAME, tokens.getPreferredUsername());
        assertNotNull(tokens.getRefreshToken());
        assertTrue(tokens.getRoles().contains("dcm4che-user"));

        String request = provider.getLastTokenRequest();
        assertTrue(request.contains("grant_type=authorization_code"));
        assertTrue(request.contains("code=" + ServletStubs.FakeOpenIdProvider.CODE));
        assertTrue(request.contains("code_verifier=verifier-1"));
        assertTrue(request.contains("client_id=" + ServletStubs.FakeOpenIdProvider.CLIENT_ID));
        assertTrue(request.contains("client_secret=" + ServletStubs.FakeOpenIdProvider.CLIENT_SECRET));
        assertTrue(request.contains("redirect_uri=https%3A%2F%2Fdcm4che.example.com%2Fbff%2Fcallback"));
    }

    @Test
    public void testPublicClientDoesNotSendSecret() throws IOException {
        Properties props = new Properties();
        props.setProperty(BffConfiguration.PROP_ISSUER_URI, provider.getIssuer());
        props.setProperty(BffConfiguration.PROP_CLIENT_ID, ServletStubs.FakeOpenIdProvider.CLIENT_ID);
        props.setProperty(BffConfiguration.PROP_REDIRECT_URI, "https://dcm4che.example.com/bff/callback");
        OpenIdClient client = OpenIdClient.create(BffConfiguration.fromProperties(props));
        client.exchangeCode(ServletStubs.FakeOpenIdProvider.CODE, "verifier-1");
        assertFalse(provider.getLastTokenRequest().contains("client_secret"));
    }

    @Test
    public void testTokenEndpointErrorIsReported() throws IOException {
        OpenIdClient client = OpenIdClient.create(configuration);
        provider.setTokenResponse("authorization_code",
                "{\"error\":\"invalid_grant\",\"error_description\":\"Code not valid\"}");
        // the fake provider answers 200 with an error document: no access token
        try {
            client.exchangeCode("wrong-code", "verifier-1");
            fail("A token response without access token must be rejected");
        } catch (IOException e) {
            assertTrue(e.getMessage().contains("access_token"));
        }
    }

    @Test
    public void testRefresh() throws IOException {
        OpenIdClient client = OpenIdClient.create(configuration);
        TokenSet tokens = client.refresh("the-refresh-token");
        assertNotNull(tokens.getAccessToken());
        String request = provider.getLastTokenRequest();
        assertTrue(request.contains("grant_type=refresh_token"));
        assertTrue(request.contains("refresh_token=the-refresh-token"));
    }

    @Test
    public void testRevoke() throws IOException {
        OpenIdClient client = OpenIdClient.create(configuration);
        client.revoke("the-refresh-token", "refresh_token");
        assertEquals("the-refresh-token", provider.getLastRevokedToken());
    }

    @Test
    public void testRevokeOfUnknownEndpointDoesNotFail() {
        OpenIdClient.ProviderMetadata metadata = new OpenIdClient.ProviderMetadata(provider.getIssuer(),
                "https://kc/auth", "https://kc/token", null, null, null);
        new OpenIdClient(configuration, metadata).revoke("token", "refresh_token");
        assertNull(provider.getLastRevokedToken());
    }

    @Test
    public void testLogoutUrl() throws IOException {
        OpenIdClient client = OpenIdClient.create(configuration);
        String url = client.getLogoutUrl("id-token-1");
        assertTrue(url.startsWith(provider.getBaseUrl() + "/realms/dcm4che/protocol/openid-connect/logout?"));
        assertTrue(url.contains("client_id=" + ServletStubs.FakeOpenIdProvider.CLIENT_ID));
        assertTrue(url.contains("post_logout_redirect_uri=https%3A%2F%2Fdcm4che.example.com%2F"));
        assertTrue(url.contains("id_token_hint=id-token-1"));
    }

    @Test
    public void testLogoutUrlWithoutEndSessionEndpoint() {
        OpenIdClient.ProviderMetadata metadata = new OpenIdClient.ProviderMetadata(provider.getIssuer(),
                "https://kc/auth", "https://kc/token", null, null, null);
        assertNull(new OpenIdClient(configuration, metadata).getLogoutUrl("id-token-1"));
    }

    @Test
    public void testFormEncoding() {
        Map<String, String> form = new java.util.LinkedHashMap<String, String>();
        form.put("a", "1 2");
        form.put("b", null);
        form.put("c", "x&y=z");
        assertEquals("a=1+2&c=x%26y%3Dz", Json.encodeForm(form));
    }
}
