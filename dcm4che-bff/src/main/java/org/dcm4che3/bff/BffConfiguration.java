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
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

package org.dcm4che3.bff;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Properties;
import java.util.Set;

/**
 * Immutable configuration of the Backend for Frontend (BFF) OpenID Connect
 * authentication, typically against a Keycloak realm.
 *
 * @author dcm4che
 */
public class BffConfiguration {

    /** Well known path, relative to the issuer URL, of the OpenID Connect discovery document. */
    public static final String WELL_KNOWN_PATH = "/.well-known/openid-configuration";

    public static final String PROP_ISSUER_URI = "bff.issuer-uri";
    public static final String PROP_CLIENT_ID = "bff.client-id";
    public static final String PROP_CLIENT_SECRET = "bff.client-secret";
    public static final String PROP_REDIRECT_URI = "bff.redirect-uri";
    public static final String PROP_POST_LOGOUT_REDIRECT_URI = "bff.post-logout-redirect-uri";
    public static final String PROP_SCOPE = "bff.scope";
    public static final String PROP_SESSION_TIMEOUT = "bff.session-timeout";
    public static final String PROP_COOKIE_NAME = "bff.cookie-name";
    public static final String PROP_COOKIE_SECURE = "bff.cookie-secure";
    public static final String PROP_BACKEND_URI = "bff.backend-uri";
    public static final String PROP_ALLOWED_REDIRECT_URIS = "bff.allowed-redirect-uris";

    public static final String DEFAULT_SCOPE = "openid profile email";
    public static final int DEFAULT_SESSION_TIMEOUT = 3600;
    public static final String DEFAULT_COOKIE_NAME = "DCM4CHE_BFF_SESSION";

    private final String issuerUri;
    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;
    private final String postLogoutRedirectUri;
    private final Set<String> scopes;
    private final int sessionTimeout;
    private final String cookieName;
    private final boolean cookieSecure;
    private final String backendUri;
    private final Set<String> allowedRedirectUris;

    public BffConfiguration(String issuerUri, String clientId, String clientSecret,
            String redirectUri, String postLogoutRedirectUri, String scope,
            int sessionTimeout, String cookieName, boolean cookieSecure, String backendUri,
            String allowedRedirectUris) {
        this.issuerUri = trimTrailingSlash(requireText(issuerUri, PROP_ISSUER_URI));
        this.clientId = requireText(clientId, PROP_CLIENT_ID);
        this.clientSecret = clientSecret == null ? null : clientSecret.trim();
        this.redirectUri = requireText(redirectUri, PROP_REDIRECT_URI);
        this.postLogoutRedirectUri = trimToNull(postLogoutRedirectUri);
        this.scopes = Collections.unmodifiableSet(parseScopes(scope));
        this.sessionTimeout = sessionTimeout > 0 ? sessionTimeout : DEFAULT_SESSION_TIMEOUT;
        this.cookieName = trimToNull(cookieName) != null ? cookieName.trim() : DEFAULT_COOKIE_NAME;
        this.cookieSecure = cookieSecure;
        this.backendUri = trimTrailingSlash(trimToNull(backendUri));
        this.allowedRedirectUris = Collections.unmodifiableSet(parseList(allowedRedirectUris));
    }

    /**
     * Creates the configuration from properties, as read from a properties file
     * or from servlet init parameters.
     */
    public static BffConfiguration fromProperties(Properties props) {
        return new BffConfiguration(
                props.getProperty(PROP_ISSUER_URI),
                props.getProperty(PROP_CLIENT_ID),
                props.getProperty(PROP_CLIENT_SECRET),
                props.getProperty(PROP_REDIRECT_URI),
                props.getProperty(PROP_POST_LOGOUT_REDIRECT_URI),
                props.getProperty(PROP_SCOPE),
                intProperty(props, PROP_SESSION_TIMEOUT, DEFAULT_SESSION_TIMEOUT),
                props.getProperty(PROP_COOKIE_NAME),
                booleanProperty(props, PROP_COOKIE_SECURE, true),
                props.getProperty(PROP_BACKEND_URI),
                props.getProperty(PROP_ALLOWED_REDIRECT_URIS));
    }

    /**
     * Loads the configuration from a classpath resource.
     */
    public static BffConfiguration load(String resource) throws IOException {
        InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(resource);
        if (in == null)
            throw new IOException("Missing classpath resource " + resource);
        Properties props = new Properties();
        try {
            Reader reader = new InputStreamReader(in, "UTF-8");
            props.load(reader);
        } finally {
            in.close();
        }
        return fromProperties(props);
    }

    public String getIssuerUri() {
        return issuerUri;
    }

    /**
     * Returns the URL of the OpenID Connect discovery document of the issuer,
     * e.g. <code>https://keycloak.example.com/realms/dcm4che/.well-known/openid-configuration</code>.
     */
    public String getDiscoveryUri() {
        return issuerUri + WELL_KNOWN_PATH;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public boolean isConfidentialClient() {
        return clientSecret != null && !clientSecret.isEmpty();
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getPostLogoutRedirectUri() {
        return postLogoutRedirectUri;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    /**
     * Returns the scopes as space separated string, as expected by the token endpoint.
     */
    public String getScope() {
        StringBuilder sb = new StringBuilder();
        for (String scope : scopes) {
            if (sb.length() > 0)
                sb.append(' ');
            sb.append(scope);
        }
        return sb.toString();
    }

    /**
     * Returns the idle timeout of a BFF session, in seconds.
     */
    public int getSessionTimeout() {
        return sessionTimeout;
    }

    public String getCookieName() {
        return cookieName;
    }

    public boolean isCookieSecure() {
        return cookieSecure;
    }

    /**
     * Returns the base URI of the protected backend, which the BFF forwards
     * authenticated requests to; may be <code>null</code> if the BFF is deployed
     * in front of it by other means.
     */
    public String getBackendUri() {
        return backendUri;
    }

    /**
     * Returns the URIs the BFF is allowed to redirect to after login, besides
     * the configured redirect URI; protects against open redirects.
     */
    public Set<String> getAllowedRedirectUris() {
        return allowedRedirectUris;
    }

    /**
     * Checks a post login redirect target against the allow list.
     */
    public boolean isAllowedRedirectUri(String uri) {
        if (uri == null)
            return false;
        if (uri.equals(redirectUri) || uri.equals(postLogoutRedirectUri))
            return true;
        for (String allowed : allowedRedirectUris)
            if (uri.startsWith(allowed))
                return true;
        return false;
    }

    /**
     * URL encodes a value with the UTF-8 character set.
     */
    public static String urlEncode(String value) {
        if (value == null)
            return "";
        try {
            return URLEncoder.encode(value, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Set<String> parseScopes(String scope) {
        String s = trimToNull(scope);
        if (s == null)
            s = DEFAULT_SCOPE;
        Set<String> result = new LinkedHashSet<String>(Arrays.asList(s.split("[\\s,]+")));
        result.remove("");
        result.add("openid");
        return result;
    }

    private static Set<String> parseList(String value) {
        String s = trimToNull(value);
        if (s == null)
            return new LinkedHashSet<String>();
        Set<String> result = new LinkedHashSet<String>();
        for (String item : s.split("[\\s,]+"))
            if (!item.isEmpty())
                result.add(trimTrailingSlash(item));
        return result;
    }

    private static int intProperty(Properties props, String name, int dflt) {
        String value = trimToNull(props.getProperty(name));
        if (value == null)
            return dflt;
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid value of property " + name + ": " + value, e);
        }
    }

    private static boolean booleanProperty(Properties props, String name, boolean dflt) {
        String value = trimToNull(props.getProperty(name));
        return value == null ? dflt : Boolean.parseBoolean(value);
    }

    private static String requireText(String value, String name) {
        String s = trimToNull(value);
        if (s == null)
            throw new IllegalArgumentException("Missing required property " + name);
        return s;
    }

    private static String trimToNull(String value) {
        if (value == null)
            return null;
        String s = value.trim();
        return s.isEmpty() ? null : s;
    }

    private static String trimTrailingSlash(String value) {
        if (value == null)
            return null;
        String s = value.trim();
        while (s.endsWith("/"))
            s = s.substring(0, s.length() - 1);
        return s;
    }

    @Override
    public String toString() {
        return "BffConfiguration[issuerUri=" + issuerUri
                + ", clientId=" + clientId
                + ", redirectUri=" + redirectUri
                + ", scope=" + getScope()
                + ", sessionTimeout=" + sessionTimeout
                + ", backendUri=" + backendUri + "]";
    }

    Collection<String> scopes() {
        return new ArrayList<String>(scopes);
    }
}
