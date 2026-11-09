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
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Tests the server side session store and the session cookie.
 */
public class BffSessionStoreTest {

    @Test
    public void testCreateAndGet() {
        BffSessionStore store = new BffSessionStore(60);
        BffSession session = store.create();
        assertNotNull(session.getId());
        assertEquals(1, store.size());
        assertSame(session, store.get(session.getId()));
        assertFalse(session.isAuthenticated());
    }

    @Test
    public void testSessionIdsAreUniqueAndOpaque() {
        BffSessionStore store = new BffSessionStore(60);
        BffSession a = store.create();
        BffSession b = store.create();
        assertFalse(a.getId().equals(b.getId()));
        // 32 random bytes, Base64 URL encoded without padding
        assertEquals(43, a.getId().length());
    }

    @Test
    public void testUnknownOrEmptyId() {
        BffSessionStore store = new BffSessionStore(60);
        assertNull(store.get(null));
        assertNull(store.get(""));
        assertNull(store.get("does-not-exist"));
    }

    @Test
    public void testIdleSessionExpires() throws Exception {
        BffSessionStore store = new BffSessionStore(1);
        BffSession session = store.create();
        assertNotNull(store.get(session.getId()));
        Thread.sleep(1200);
        assertNull(store.get(session.getId()));
        assertEquals(0, store.size());
    }

    @Test
    public void testAccessRefreshesIdleTimeout() throws Exception {
        BffSessionStore store = new BffSessionStore(2);
        BffSession session = store.create();
        for (int i = 0; i < 3; i++) {
            Thread.sleep(800);
            assertNotNull(store.get(session.getId()));
        }
    }

    @Test
    public void testExpiredSessionsAreEvictedOnCreate() throws Exception {
        BffSessionStore store = new BffSessionStore(0);
        BffSession first = store.create();
        Thread.sleep(10);
        store.create();
        assertNull(store.peek(first.getId()));
        assertEquals(1, store.size());
    }

    @Test
    public void testRemove() {
        BffSessionStore store = new BffSessionStore(60);
        BffSession session = store.create();
        store.remove(session.getId());
        assertNull(store.get(session.getId()));
        assertEquals(0, store.size());
    }

    @Test
    public void testSessionHoldsTokensAndClearsThem() {
        BffSession session = new BffSession("id", System.currentTimeMillis());
        session.startAuthorization("state-1", "nonce-1", "verifier-1", "/index.html");
        assertEquals("state-1", session.getState());
        assertFalse(session.isAuthenticated());

        session.setTokens(JsonAndTokenTest.tokens("{\"sub\":\"u1\"}"));
        assertTrue(session.isAuthenticated());
        assertNull(session.getState());
        assertNull(session.getNonce());
        assertNull(session.getCodeVerifier());
        assertEquals("/index.html", session.getRedirectUri());

        session.clear();
        assertFalse(session.isAuthenticated());
    }

    @Test
    public void testCookieHeaderIsHardened() {
        BffConfiguration configuration = BffConfiguration.fromProperties(configurationProperties(true));
        SessionCookie cookie = new SessionCookie(configuration);
        String header = cookie.header("abc", 3600);
        assertTrue(header.startsWith("DCM4CHE_BFF_SESSION=abc"));
        assertTrue(header.contains("HttpOnly"));
        assertTrue(header.contains("Secure"));
        assertTrue(header.contains("SameSite=Lax"));
        assertTrue(header.contains("Path=/bff"));
        assertTrue(header.contains("Max-Age=3600"));

        String cleared = cookie.header("", 0);
        assertTrue(cleared.contains("Max-Age=0"));
    }

    @Test
    public void testInsecureCookieWhenConfigured() {
        BffConfiguration configuration = BffConfiguration.fromProperties(configurationProperties(false));
        String header = new SessionCookie(configuration).header("abc", 60);
        assertFalse(header.contains("Secure"));
        assertTrue(header.contains("HttpOnly"));
    }

    @Test
    public void testProxyPathsAndPrefixes() {
        SessionCookie cookie = new SessionCookie("SID", true, "/bff");
        assertEquals("SID", cookie.getName());
        assertEquals("/bff", cookie.getPath());
    }

    private static java.util.Properties configurationProperties(boolean secure) {
        java.util.Properties props = new java.util.Properties();
        props.setProperty(BffConfiguration.PROP_ISSUER_URI, "https://keycloak.example.com/realms/dcm4che");
        props.setProperty(BffConfiguration.PROP_CLIENT_ID, "dcm4che-bff");
        props.setProperty(BffConfiguration.PROP_REDIRECT_URI, "https://dcm4che.example.com/bff/callback");
        props.setProperty(BffConfiguration.PROP_COOKIE_SECURE, Boolean.toString(secure));
        return props;
    }
}
