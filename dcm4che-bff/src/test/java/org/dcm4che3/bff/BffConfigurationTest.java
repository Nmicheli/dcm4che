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
import java.util.Properties;

import org.junit.Test;

/**
 * Tests the parsing and validation of the BFF configuration.
 */
public class BffConfigurationTest {

    private static Properties props() {
        Properties props = new Properties();
        props.setProperty(BffConfiguration.PROP_ISSUER_URI, "https://keycloak.example.com/realms/dcm4che/");
        props.setProperty(BffConfiguration.PROP_CLIENT_ID, "dcm4che-bff");
        props.setProperty(BffConfiguration.PROP_CLIENT_SECRET, "secret");
        props.setProperty(BffConfiguration.PROP_REDIRECT_URI, "https://dcm4che.example.com/bff/callback");
        props.setProperty(BffConfiguration.PROP_BACKEND_URI, "https://dcm4che.example.com/api/");
        return props;
    }

    @Test
    public void testDiscoveryUriFromIssuer() {
        BffConfiguration configuration = BffConfiguration.fromProperties(props());
        assertEquals("https://keycloak.example.com/realms/dcm4che", configuration.getIssuerUri());
        assertEquals("https://keycloak.example.com/realms/dcm4che/.well-known/openid-configuration",
                configuration.getDiscoveryUri());
        assertEquals("https://dcm4che.example.com/api", configuration.getBackendUri());
    }

    @Test
    public void testDefaults() {
        BffConfiguration configuration = BffConfiguration.fromProperties(props());
        assertEquals("openid profile email", configuration.getScope());
        assertEquals(BffConfiguration.DEFAULT_SESSION_TIMEOUT, configuration.getSessionTimeout());
        assertEquals(BffConfiguration.DEFAULT_COOKIE_NAME, configuration.getCookieName());
        assertTrue(configuration.isCookieSecure());
        assertTrue(configuration.isConfidentialClient());
        assertNull(configuration.getPostLogoutRedirectUri());
    }

    @Test
    public void testScopeAlwaysContainsOpenid() {
        Properties props = props();
        props.setProperty(BffConfiguration.PROP_SCOPE, "profile email");
        BffConfiguration configuration = BffConfiguration.fromProperties(props);
        assertTrue(configuration.getScopes().contains("openid"));
        assertEquals("profile email openid", configuration.getScope());

        props.setProperty(BffConfiguration.PROP_SCOPE, "openid,profile");
        assertEquals("openid profile", BffConfiguration.fromProperties(props).getScope());
    }

    @Test
    public void testPublicClientHasNoSecret() {
        Properties props = props();
        props.remove(BffConfiguration.PROP_CLIENT_SECRET);
        BffConfiguration configuration = BffConfiguration.fromProperties(props);
        assertFalse(configuration.isConfidentialClient());
        assertNull(configuration.getClientSecret());

        props.setProperty(BffConfiguration.PROP_CLIENT_SECRET, "   ");
        assertFalse(BffConfiguration.fromProperties(props).isConfidentialClient());
    }

    @Test
    public void testMissingIssuerIsRejected() {
        Properties props = props();
        props.remove(BffConfiguration.PROP_ISSUER_URI);
        try {
            BffConfiguration.fromProperties(props);
            fail("Missing issuer must be rejected");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains(BffConfiguration.PROP_ISSUER_URI));
        }
    }

    @Test
    public void testMissingClientIdIsRejected() {
        Properties props = props();
        props.remove(BffConfiguration.PROP_CLIENT_ID);
        try {
            BffConfiguration.fromProperties(props);
            fail("Missing client id must be rejected");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains(BffConfiguration.PROP_CLIENT_ID));
        }
    }

    @Test
    public void testInvalidSessionTimeoutIsRejected() {
        Properties props = props();
        props.setProperty(BffConfiguration.PROP_SESSION_TIMEOUT, "half an hour");
        try {
            BffConfiguration.fromProperties(props);
            fail("Invalid session timeout must be rejected");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains(BffConfiguration.PROP_SESSION_TIMEOUT));
        }
    }

    @Test
    public void testRedirectAllowList() {
        Properties props = props();
        props.setProperty(BffConfiguration.PROP_POST_LOGOUT_REDIRECT_URI, "https://dcm4che.example.com/bye");
        props.setProperty(BffConfiguration.PROP_ALLOWED_REDIRECT_URIS,
                "https://dcm4che.example.com/, https://viewer.example.com");
        BffConfiguration configuration = BffConfiguration.fromProperties(props);
        assertEquals(2, configuration.getAllowedRedirectUris().size());
        assertTrue(configuration.isAllowedRedirectUri("https://dcm4che.example.com/"));
        assertTrue(configuration.isAllowedRedirectUri("https://dcm4che.example.com/studies/1"));
        assertTrue(configuration.isAllowedRedirectUri("https://viewer.example.com/index.html"));
        assertTrue(configuration.isAllowedRedirectUri("https://dcm4che.example.com/bff/callback"));
        assertTrue(configuration.isAllowedRedirectUri("https://dcm4che.example.com/bye"));
        assertFalse(configuration.isAllowedRedirectUri("https://evil.example.org/"));
        assertFalse(configuration.isAllowedRedirectUri("//evil.example.org/"));
        assertFalse(configuration.isAllowedRedirectUri(null));
    }

    @Test
    public void testLoadFromClasspath() throws IOException {
        BffConfiguration configuration = BffConfiguration.load("bff.properties");
        assertNotNull(configuration.getIssuerUri());
        assertEquals("dcm4che-bff", configuration.getClientId());
        assertFalse(configuration.isConfidentialClient());
    }

    @Test
    public void testUrlEncode() {
        assertEquals("openid+profile+email", BffConfiguration.urlEncode("openid profile email"));
        assertEquals("https%3A%2F%2Fdcm4che.example.com%2Fbff%2Fcallback",
                BffConfiguration.urlEncode("https://dcm4che.example.com/bff/callback"));
        assertEquals("", BffConfiguration.urlEncode(null));
    }
}
