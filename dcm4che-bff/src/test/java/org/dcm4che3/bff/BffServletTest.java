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
 * Tests the BFF endpoints end to end against a fake OpenID Connect provider:
 * login, callback, user info, status, logout and the authenticated proxy.
 */
public class BffServletTest {

    private ServletStubs.FakeOpenIdProvider provider;
    private BffConfiguration configuration;
    private BffServlet servlet;

    @Before
    public void setUp() throws IOException {
        provider = new ServletStubs.FakeOpenIdProvider();
        Properties props = new Properties();
        props.setProperty(BffConfiguration.PROP_ISSUER_URI, provider.getIssuer());
        props.setProperty(BffConfiguration.PROP_CLIENT_ID, ServletStubs.FakeOpenIdProvider.CLIENT_ID);
        props.setProperty(BffConfiguration.PROP_CLIENT_SECRET, ServletStubs.FakeOpenIdProvider.CLIENT_SECRET);
        props.setProperty(BffConfiguration.PROP_REDIRECT_URI, "https://dcm4che.example.com/bff/callback");
        props.setProperty(BffConfiguration.PROP_POST_LOGOUT_REDIRECT_URI, "https://dcm4che.example.com/");
        props.setProperty(BffConfiguration.PROP_ALLOWED_REDIRECT_URIS, "https://dcm4che.example.com/");
        props.setProperty(BffConfiguration.PROP_BACKEND_URI, provider.getBackendUrl());
        props.setProperty(BffConfiguration.PROP_COOKIE_SECURE, "false");
        configuration = BffConfiguration.fromProperties(props);
        servlet = new BffServlet(configuration, OpenIdClient.create(configuration));
    }

    @After
    public void tearDown() {
        provider.stop();
    }

    @Test
    public void testLoginRedirectsToProviderWithPkce() throws Exception {
        ServletStubs.Request request = new ServletStubs.Request().pathInfo("/login");
        ServletStubs.Response response = new ServletStubs.Response();
        servlet.login(request, response);

        assertEquals(302, response.getStatus());
        String location = response.getRedirect();
        assertNotNull(location);
        assertTrue(location.startsWith(provider.getBaseUrl() + "/realms/dcm4che/protocol/openid-connect/auth?"));
        assertTrue(location.contains("code_challenge_method=S256"));
        assertTrue(location.contains("state="));
        assertTrue(location.contains("nonce="));
        assertFalse(location.contains(ServletStubs.FakeOpenIdProvider.CLIENT_SECRET));

        String sessionId = ServletStubs.sessionCookieValue(response);
        BffSession session = servlet.getSessionStore().get(sessionId);
        assertNotNull(session);
        assertNotNull(session.getState());
        assertNotNull(session.getNonce());
        assertNotNull(session.getCodeVerifier());
        // the code verifier never leaves the server
        assertFalse(location.contains(session.getCodeVerifier()));
        // and the state in the URL is the one stored in the session
        assertTrue(location.contains("state=" + session.getState()));
    }

    @Test
    public void testLoginRejectsRedirectOutsideAllowList() throws Exception {
        ServletStubs.Request request = new ServletStubs.Request().pathInfo("/login")
                .parameter("redirect", "https://evil.example.org/steal");
        ServletStubs.Response response = new ServletStubs.Response();
        servlet.login(request, response);
        assertEquals(400, response.getStatus());
        assertNull(response.getRedirect());
        assertTrue(response.body().contains("not allowed"));
    }

    @Test
    public void testLoginAcceptsAllowedRedirect() throws Exception {
        ServletStubs.Request request = new ServletStubs.Request().pathInfo("/login")
                .parameter("redirect", "https://dcm4che.example.com/viewer");
        ServletStubs.Response response = new ServletStubs.Response();
        servlet.login(request, response);
        assertEquals(302, response.getStatus());
        String sessionId = ServletStubs.sessionCookieValue(response);
        assertEquals("https://dcm4che.example.com/viewer",
                servlet.getSessionStore().get(sessionId).getRedirectUri());
    }

    @Test
    public void testCallbackCompletesTheLogin() throws Exception {
        String sessionId = login();
        BffSession session = servlet.getSessionStore().get(sessionId);

        ServletStubs.Request request = new ServletStubs.Request().pathInfo("/callback")
                .sessionCookie(sessionId)
                .parameter("code", ServletStubs.FakeOpenIdProvider.CODE)
                .parameter("state", session.getState());
        ServletStubs.Response response = new ServletStubs.Response();
        servlet.callback(request, response);

        assertEquals(302, response.getStatus());
        assertEquals("https://dcm4che.example.com/bff/callback", response.getRedirect());
        assertNotNull("session cookie must be refreshed", response.header("set-cookie"));

        BffSession authenticated = servlet.getSessionStore().get(sessionId);
        assertTrue(authenticated.isAuthenticated());
        assertEquals(ServletStubs.FakeOpenIdProvider.SUBJECT, authenticated.getTokens().getSubject());
        assertNull("the state must be single use", authenticated.getState());
        assertNull(authenticated.getCodeVerifier());

        String tokenRequest = provider.getLastTokenRequest();
        assertTrue(tokenRequest.contains("grant_type=authorization_code"));
        assertTrue(tokenRequest.contains("code=" + ServletStubs.FakeOpenIdProvider.CODE));
        assertTrue(tokenRequest.contains("code_verifier="));
        assertNull("the code verifier must be single use", session.getCodeVerifier());
    }

    @Test
    public void testCallbackWithWrongStateIsRejected() throws Exception {
        String sessionId = login();
        ServletStubs.Request request = new ServletStubs.Request().pathInfo("/callback")
                .sessionCookie(sessionId)
                .parameter("code", ServletStubs.FakeOpenIdProvider.CODE)
                .parameter("state", "forged-state");
        ServletStubs.Response response = new ServletStubs.Response();
        servlet.callback(request, response);

        assertEquals(401, response.getStatus());
        ServletStubs.assertSessionCleared(response);
        assertNull(servlet.getSessionStore().get(sessionId));
        assertNull("no token request must be sent", provider.getLastTokenRequest());
    }

    @Test
    public void testCallbackWithoutSessionIsRejected() throws Exception {
        ServletStubs.Request request = new ServletStubs.Request().pathInfo("/callback")
                .parameter("code", ServletStubs.FakeOpenIdProvider.CODE)
                .parameter("state", "whatever");
        ServletStubs.Response response = new ServletStubs.Response();
        servlet.callback(request, response);
        assertEquals(401, response.getStatus());
        assertTrue(response.body().contains("No pending login"));
    }

    @Test
    public void testCallbackWithoutCodeIsRejected() throws Exception {
        String sessionId = login();
        ServletStubs.Request request = new ServletStubs.Request().pathInfo("/callback")
                .sessionCookie(sessionId)
                .parameter("state", servlet.getSessionStore().get(sessionId).getState());
        ServletStubs.Response response = new ServletStubs.Response();
        servlet.callback(request, response);
        assertEquals(400, response.getStatus());
    }

    @Test
    public void testCallbackWithProviderErrorIsRejected() throws Exception {
        String sessionId = login();
        ServletStubs.Request request = new ServletStubs.Request().pathInfo("/callback")
                .sessionCookie(sessionId)
                .parameter("error", "access_denied");
        ServletStubs.Response response = new ServletStubs.Response();
        servlet.callback(request, response);
        assertEquals(401, response.getStatus());
        assertTrue(response.body().contains("access_denied"));
        ServletStubs.assertSessionCleared(response);
    }

    @Test
    public void testCallbackRejectsIdTokenOfAnotherAudience() throws Exception {
        String sessionId = login();
        BffSession session = servlet.getSessionStore().get(sessionId);
        provider.setTokenResponse("authorization_code", idTokenResponse(null, "another-client"));

        ServletStubs.Request request = new ServletStubs.Request().pathInfo("/callback")
                .sessionCookie(sessionId)
                .parameter("code", ServletStubs.FakeOpenIdProvider.CODE)
                .parameter("state", session.getState());
        ServletStubs.Response response = new ServletStubs.Response();
        try {
            servlet.callback(request, response);
            fail("An ID token of another audience must be rejected");
        } catch (TokenValidator.TokenValidationException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("client"));
        }
        assertFalse("the session must not be authenticated", session.isAuthenticated());
        assertNull(session.getTokens());
    }

    @Test
    public void testCallbackRejectsIdTokenWithWrongNonce() throws Exception {
        String sessionId = login();
        BffSession session = servlet.getSessionStore().get(sessionId);
        provider.setTokenResponse("authorization_code", idTokenResponse("replayed-nonce", null));

        ServletStubs.Request request = new ServletStubs.Request().pathInfo("/callback")
                .sessionCookie(sessionId)
                .parameter("code", ServletStubs.FakeOpenIdProvider.CODE)
                .parameter("state", session.getState());
        ServletStubs.Response response = new ServletStubs.Response();
        try {
            servlet.callback(request, response);
            fail("An ID token with a foreign nonce must be rejected");
        } catch (TokenValidator.TokenValidationException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("nonce"));
        }
        assertFalse(session.isAuthenticated());
    }

    @Test
    public void testUserInfoAndStatus() throws Exception {
        String sessionId = authenticatedSession();

        ServletStubs.Response status = new ServletStubs.Response();
        servlet.status(new ServletStubs.Request().pathInfo("/status").sessionCookie(sessionId), status);
        assertEquals(200, status.getStatus());
        assertTrue(status.body().contains("\"authenticated\":true"));
        assertTrue(status.body().contains(ServletStubs.FakeOpenIdProvider.USERNAME));
        assertEquals("no-store", status.header("cache-control"));

        ServletStubs.Response userinfo = new ServletStubs.Response();
        servlet.userinfo(new ServletStubs.Request().pathInfo("/userinfo").sessionCookie(sessionId), userinfo);
        assertEquals(200, userinfo.getStatus());
        Map<String, Object> info = Json.parseObject(userinfo.body());
        assertEquals(ServletStubs.FakeOpenIdProvider.SUBJECT, info.get("sub"));
        assertEquals(ServletStubs.FakeOpenIdProvider.USERNAME, info.get("preferred_username"));
        assertEquals("jdoe@example.com", info.get("email"));
        assertFalse(info.containsKey("access_token"));
        assertFalse(info.containsKey("id_token"));
    }

    @Test
    public void testStatusOfAnonymousRequest() throws Exception {
        ServletStubs.Response status = new ServletStubs.Response();
        servlet.status(new ServletStubs.Request().pathInfo("/status"), status);
        assertTrue(status.body().contains("\"authenticated\":false"));
    }

    @Test
    public void testUserInfoRequiresAuthentication() throws Exception {
        ServletStubs.Response response = new ServletStubs.Response();
        servlet.userinfo(new ServletStubs.Request().pathInfo("/userinfo"), response);
        assertEquals(401, response.getStatus());
    }

    @Test
    public void testLogoutRevokesTokensAndClearsTheCookie() throws Exception {
        String sessionId = authenticatedSession();
        ServletStubs.Response response = new ServletStubs.Response();
        servlet.logout(new ServletStubs.Request().pathInfo("/logout").sessionCookie(sessionId), response);

        assertEquals(200, response.getStatus());
        assertTrue(response.body().contains("post_logout_redirect_uri"));
        assertEquals("the-refresh-token", provider.getLastRevokedToken());
        ServletStubs.assertSessionCleared(response);
        assertNull(servlet.getSessionStore().get(sessionId));
    }

    @Test
    public void testProxyInjectsBearerTokenAndStripsBrowserCredentials() throws Exception {
        String sessionId = authenticatedSession();
        BffProxyServlet proxy = new BffProxyServlet(servlet);

        ServletStubs.Request request = new ServletStubs.Request().pathInfo("/studies/1").sessionCookie(sessionId);
        ServletStubs.Response response = new ServletStubs.Response();
        proxy.service(request, response);

        assertEquals(200, response.getStatus());
        assertTrue(response.body().contains("studies"));
        assertEquals("/backend/studies/1", provider.getLastBackendPath());
        String authorization = provider.getLastBackendAuthorization();
        assertNotNull(authorization);
        assertTrue(authorization.startsWith("Bearer ey"));
        assertFalse("the session cookie must not be forwarded", authorization.contains(sessionId));
    }

    @Test
    public void testProxyRejectsAnonymousRequests() throws Exception {
        BffProxyServlet proxy = new BffProxyServlet(servlet);
        ServletStubs.Response response = new ServletStubs.Response();
        proxy.service(new ServletStubs.Request().pathInfo("/studies"), response);
        assertEquals(401, response.getStatus());
        assertNull(provider.getLastBackendPath());
    }

    @Test
    public void testProxyWithoutBackendIsNotImplemented() throws Exception {
        Properties props = new Properties();
        props.setProperty(BffConfiguration.PROP_ISSUER_URI, provider.getIssuer());
        props.setProperty(BffConfiguration.PROP_CLIENT_ID, ServletStubs.FakeOpenIdProvider.CLIENT_ID);
        props.setProperty(BffConfiguration.PROP_REDIRECT_URI, "https://dcm4che.example.com/bff/callback");
        BffConfiguration noBackend = BffConfiguration.fromProperties(props);
        BffServlet other = new BffServlet(noBackend, OpenIdClient.create(noBackend));
        ServletStubs.Response response = new ServletStubs.Response();
        new BffProxyServlet(other).service(new ServletStubs.Request().pathInfo("/studies"), response);
        assertEquals(501, response.getStatus());
    }

    @Test
    public void testExpiredAccessTokenIsRefreshed() throws Exception {
        String sessionId = authenticatedSession();
        BffSession session = servlet.getSessionStore().get(sessionId);
        // an access token that is about to expire
        Map<String, Object> response = Json.parseObject(idTokenResponse(session.getNonce(), null));
        TokenSet nearExpiry = TokenSet.fromTokenResponse(response, System.currentTimeMillis() - 290000L);
        assertTrue(nearExpiry.getExpiresAt() - System.currentTimeMillis() < 30000);
        session.setTokens(nearExpiry);

        ServletStubs.Request request = new ServletStubs.Request().pathInfo("/studies").sessionCookie(sessionId);
        TokenSet tokens = servlet.authenticate(request);
        assertNotNull(tokens);
        assertTrue(provider.getLastTokenRequest().contains("grant_type=refresh_token"));
        assertTrue(session.getTokens().getExpiresAt() - System.currentTimeMillis() > 60000);
    }

    private String login() throws Exception {
        ServletStubs.Response response = new ServletStubs.Response();
        servlet.login(new ServletStubs.Request().pathInfo("/login"), response);
        assertEquals(302, response.getStatus());
        return ServletStubs.sessionCookieValue(response);
    }

    private String authenticatedSession() throws Exception {
        String sessionId = login();
        BffSession session = servlet.getSessionStore().get(sessionId);
        ServletStubs.Response response = new ServletStubs.Response();
        servlet.callback(new ServletStubs.Request().pathInfo("/callback")
                .sessionCookie(sessionId)
                .parameter("code", ServletStubs.FakeOpenIdProvider.CODE)
                .parameter("state", session.getState()), response);
        assertEquals(302, response.getStatus());
        return sessionId;
    }

    private String idTokenResponse(String nonce, String audience) {
        long now = System.currentTimeMillis() / 1000L;
        String claims = "{\"iss\":" + Json.quote(provider.getIssuer())
                + ",\"sub\":\"" + ServletStubs.FakeOpenIdProvider.SUBJECT + "\""
                + ",\"aud\":" + Json.quote(audience != null ? audience : ServletStubs.FakeOpenIdProvider.CLIENT_ID)
                + ",\"exp\":" + (now + 300) + ",\"iat\":" + now
                + (nonce != null ? ",\"nonce\":" + Json.quote(nonce) : "")
                + "}";
        String idToken = "eyJhbGciOiJSUzI1NiJ9." + TokenSet.base64UrlEncode(Json.utf8(claims)) + ".signature";
        return "{\"access_token\":\"an-access-token\",\"refresh_token\":\"a-refresh-token\","
                + "\"expires_in\":300,\"token_type\":\"Bearer\","
                + "\"id_token\":" + Json.quote(idToken) + "}";
    }
}
