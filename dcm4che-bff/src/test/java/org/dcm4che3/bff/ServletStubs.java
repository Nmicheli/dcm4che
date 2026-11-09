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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.servlet.AsyncContext;
import javax.servlet.DispatcherType;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRegistration;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.Part;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

/**
 * Minimal in-memory test doubles for the Servlet API, so that the BFF can be
 * tested without a servlet container, and a fake OpenID Connect provider.
 * <p>
 * Only the methods used by the BFF behave; the others throw
 * {@link UnsupportedOperationException}.
 */
final class ServletStubs {

    private ServletStubs() {
    }

    static final class Request implements HttpServletRequest {

        private final Map<String, String> parameters = new HashMap<String, String>();
        private final Map<String, Object> attributes = new HashMap<String, Object>();
        private String pathInfo;
        private String cookie;
        private final byte[] body;

        Request() {
            this(new byte[0]);
        }

        Request(byte[] body) {
            this.body = body;
        }

        Request pathInfo(String pathInfo) {
            this.pathInfo = pathInfo;
            return this;
        }

        Request parameter(String name, String value) {
            parameters.put(name, value);
            return this;
        }

        Request sessionCookie(String value) {
            this.cookie = value;
            return this;
        }

        Object attribute(String name) {
            return attributes.get(name);
        }

        // ---- used by the BFF ------------------------------------------------

        public String getParameter(String name) {
            return parameters.get(name);
        }

        public String getPathInfo() {
            return pathInfo;
        }

        public Cookie[] getCookies() {
            if (cookie == null)
                return null;
            Cookie c = new Cookie("DCM4CHE_BFF_SESSION", cookie);
            c.setPath("/bff");
            return new Cookie[] { c };
        }

        public Object getAttribute(String name) {
            return attributes.get(name);
        }

        public void setAttribute(String name, Object value) {
            if (value == null)
                attributes.remove(name);
            else
                attributes.put(name, value);
        }

        public void removeAttribute(String name) {
            attributes.remove(name);
        }

        public String getMethod() {
            return "GET";
        }

        public String getContextPath() {
            return "";
        }

        public String getServletPath() {
            return "/bff";
        }

        public String getRequestURI() {
            return "/bff" + (pathInfo != null ? pathInfo : "");
        }

        public String getQueryString() {
            return null;
        }

        public ServletInputStream getInputStream() {
            final java.io.ByteArrayInputStream in = new java.io.ByteArrayInputStream(body);
            return new ServletInputStream() {
                public int read() {
                    return in.read();
                }

                @Override
                public int read(byte[] b, int off, int len) {
                    return in.read(b, off, len);
                }
            };
        }

        public String getHeader(String name) {
            return null;
        }

        public Enumeration<String> getHeaders(String name) {
            return Collections.enumeration(Collections.<String> emptyList());
        }

        public Enumeration<String> getHeaderNames() {
            return Collections.enumeration(Collections.<String> emptyList());
        }

        public String getCharacterEncoding() {
            return "UTF-8";
        }

        public String[] getParameterValues(String name) {
            return parameters.containsKey(name) ? new String[] { parameters.get(name) } : null;
        }

        public Locale getLocale() {
            return Locale.ITALY;
        }

        public String getRemoteAddr() {
            return "127.0.0.1";
        }

        // ---- unused ---------------------------------------------------------

        public String getAuthType() {
            throw new UnsupportedOperationException();
        }

        public long getDateHeader(String name) {
            return -1;
        }

        public int getIntHeader(String name) {
            return -1;
        }

        public String getPathTranslated() {
            return null;
        }

        public String getRemoteUser() {
            return null;
        }

        public boolean isUserInRole(String role) {
            return false;
        }

        public java.security.Principal getUserPrincipal() {
            return null;
        }

        public String getRequestedSessionId() {
            return null;
        }

        public StringBuffer getRequestURL() {
            return new StringBuffer("http://127.0.0.1:8080/bff");
        }

        public HttpSession getSession(boolean create) {
            throw new UnsupportedOperationException();
        }

        public HttpSession getSession() {
            throw new UnsupportedOperationException();
        }

        public boolean isRequestedSessionIdValid() {
            return false;
        }

        public boolean isRequestedSessionIdFromCookie() {
            return cookie != null;
        }

        public boolean isRequestedSessionIdFromURL() {
            return false;
        }

        public boolean isRequestedSessionIdFromUrl() {
            return false;
        }

        public boolean authenticate(HttpServletResponse response) {
            return false;
        }

        public void login(String username, String password) {
            throw new UnsupportedOperationException();
        }

        public void logout() {
            throw new UnsupportedOperationException();
        }

        public Collection<Part> getParts() {
            throw new UnsupportedOperationException();
        }

        public Part getPart(String name) {
            throw new UnsupportedOperationException();
        }

        public void setCharacterEncoding(String env) {
            throw new UnsupportedOperationException();
        }

        public int getContentLength() {
            return body.length;
        }

        public String getContentType() {
            return null;
        }

        public String getProtocol() {
            return "HTTP/1.1";
        }

        public String getScheme() {
            return "http";
        }

        public String getServerName() {
            return "127.0.0.1";
        }

        public int getServerPort() {
            return 8080;
        }

        public java.io.BufferedReader getReader() {
            throw new UnsupportedOperationException();
        }

        public String getRemoteHost() {
            return "127.0.0.1";
        }

        public Enumeration<String> getAttributeNames() {
            return Collections.enumeration(attributes.keySet());
        }

        public Enumeration<String> getParameterNames() {
            return Collections.enumeration(parameters.keySet());
        }

        public Map<String, String[]> getParameterMap() {
            Map<String, String[]> map = new HashMap<String, String[]>();
            for (Map.Entry<String, String> e : parameters.entrySet())
                map.put(e.getKey(), new String[] { e.getValue() });
            return map;
        }

        public Enumeration<Locale> getLocales() {
            return Collections.enumeration(Collections.<Locale> emptyList());
        }

        public boolean isSecure() {
            return false;
        }

        public RequestDispatcher getRequestDispatcher(String path) {
            throw new UnsupportedOperationException();
        }

        public String getRealPath(String path) {
            return null;
        }

        public int getRemotePort() {
            return 12345;
        }

        public String getLocalName() {
            return "localhost";
        }

        public String getLocalAddr() {
            return "127.0.0.1";
        }

        public int getLocalPort() {
            return 8080;
        }

        public ServletContext getServletContext() {
            throw new UnsupportedOperationException();
        }

        public AsyncContext startAsync() {
            throw new UnsupportedOperationException();
        }

        public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse) {
            throw new UnsupportedOperationException();
        }

        public boolean isAsyncStarted() {
            return false;
        }

        public boolean isAsyncSupported() {
            return false;
        }

        public AsyncContext getAsyncContext() {
            throw new UnsupportedOperationException();
        }

        public DispatcherType getDispatcherType() {
            return DispatcherType.REQUEST;
        }
    }

    static final class Response implements HttpServletResponse {

        private final ByteArrayOutputStream body = new ByteArrayOutputStream();
        private final Map<String, String> headers = new HashMap<String, String>();
        private int status = 200;
        private String redirect;

        String body() {
            return new String(body.toByteArray(), Charset.forName("UTF-8"));
        }

        String header(String name) {
            return headers.get(name.toLowerCase());
        }

        String getRedirect() {
            return redirect;
        }

        // ---- used by the BFF ------------------------------------------------

        public void addHeader(String name, String value) {
            headers.put(name.toLowerCase(), value);
        }

        public void setHeader(String name, String value) {
            headers.put(name.toLowerCase(), value);
        }

        public void setStatus(int sc) {
            this.status = sc;
        }

        public void setStatus(int sc, String message) {
            this.status = sc;
        }

        public void sendRedirect(String location) {
            this.status = 302;
            this.redirect = location;
            headers.put("location", location);
        }

        public void setContentType(String type) {
            headers.put("content-type", type);
        }

        public void setCharacterEncoding(String charset) {
            headers.put("character-encoding", charset);
        }

        public PrintWriter getWriter() {
            return new PrintWriter(new java.io.OutputStreamWriter(body, Charset.forName("UTF-8")), true);
        }

        public ServletOutputStream getOutputStream() {
            return new ServletOutputStream() {
                public void write(int b) {
                    body.write(b);
                }

                @Override
                public void write(byte[] b, int off, int len) {
                    body.write(b, off, len);
                }
            };
        }

        public void addCookie(Cookie cookie) {
            addHeader("Set-Cookie", cookie.getName() + "=" + cookie.getValue());
        }

        public boolean containsHeader(String name) {
            return headers.containsKey(name.toLowerCase());
        }

        public String getHeader(String name) {
            return headers.get(name.toLowerCase());
        }

        public Collection<String> getHeaders(String name) {
            String value = headers.get(name.toLowerCase());
            return value == null ? Collections.<String> emptyList() : Collections.singletonList(value);
        }

        public Collection<String> getHeaderNames() {
            return headers.keySet();
        }

        public int getStatus() {
            return status;
        }

        public void reset() {
            body.reset();
            headers.clear();
            status = 200;
            redirect = null;
        }

        // ---- unused ---------------------------------------------------------

        public void sendError(int sc) {
            this.status = sc;
        }

        public void sendError(int sc, String msg) {
            this.status = sc;
        }

        public void setContentLength(int len) {
        }

        public void setBufferSize(int size) {
        }

        public int getBufferSize() {
            return 0;
        }

        public void flushBuffer() {
        }

        public void resetBuffer() {
            body.reset();
        }

        public boolean isCommitted() {
            return false;
        }

        public void setLocale(Locale loc) {
        }

        public Locale getLocale() {
            return Locale.ITALY;
        }

        public String getCharacterEncoding() {
            return "UTF-8";
        }

        public String getContentType() {
            return headers.get("content-type");
        }

        public String encodeURL(String url) {
            return url;
        }

        public String encodeRedirectURL(String url) {
            return url;
        }

        public String encodeUrl(String url) {
            return url;
        }

        public String encodeRedirectUrl(String url) {
            return url;
        }

        public void setDateHeader(String name, long date) {
        }

        public void addDateHeader(String name, long date) {
        }

        public void setIntHeader(String name, int value) {
        }

        public void addIntHeader(String name, int value) {
        }
    }

    /**
     * Asserts that the response carries a cleared session cookie.
     */
    static void assertSessionCleared(Response response) {
        String cookie = response.header("set-cookie");
        assertNotNull("missing Set-Cookie", cookie);
        assertTrue(cookie, cookie.contains("Max-Age=0"));
        assertTrue(cookie, cookie.contains("HttpOnly"));
    }

    /**
     * Returns the value of the session cookie set by the response.
     */
    static String sessionCookieValue(Response response) {
        String cookie = response.header("set-cookie");
        assertNotNull("missing Set-Cookie", cookie);
        assertFalse("session must not be cleared", cookie.contains("Max-Age=0"));
        int start = cookie.indexOf('=') + 1;
        int end = cookie.indexOf(';');
        assertTrue("malformed cookie " + cookie, end > start);
        return cookie.substring(start, end);
    }

    static void assertNoSessionCookie(Response response) {
        assertNull(response.header("set-cookie"));
    }

    /**
     * A minimal OpenID Connect provider: discovery document, token endpoint,
     * revocation endpoint and a protected backend that echoes the credentials it
     * received. No Keycloak instance is required to run the tests.
     */
    static final class FakeOpenIdProvider {

        static final String CLIENT_ID = "dcm4che-bff";
        static final String CLIENT_SECRET = "s3cr3t";
        static final String CODE = "the-authorization-code";
        static final String SUBJECT = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
        static final String USERNAME = "jdoe";

        private final HttpServer server;
        private final String baseUrl;
        private final Map<String, String> tokenResponses = new HashMap<String, String>();
        private volatile String lastTokenRequest;
        private volatile String lastBackendPath;
        private volatile String lastBackendAuthorization;
        private volatile String lastRevokedToken;

        FakeOpenIdProvider() throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
            server.createContext("/realms/dcm4che/.well-known/openid-configuration", new HttpHandler() {
                public void handle(HttpExchange exchange) throws IOException {
                    respond(exchange, 200, discoveryDocument());
                }
            });
            server.createContext("/realms/dcm4che/protocol/openid-connect/token", new HttpHandler() {
                public void handle(HttpExchange exchange) throws IOException {
                    handleToken(exchange);
                }
            });
            server.createContext("/realms/dcm4che/protocol/openid-connect/revoke", new HttpHandler() {
                public void handle(HttpExchange exchange) throws IOException {
                    lastRevokedToken = formParameter(readBody(exchange), "token");
                    respond(exchange, 200, "{}");
                }
            });
            server.createContext("/backend/", new HttpHandler() {
                public void handle(HttpExchange exchange) throws IOException {
                    lastBackendPath = exchange.getRequestURI().getPath();
                    lastBackendAuthorization = exchange.getRequestHeaders().getFirst("Authorization");
                    respond(exchange, 200, "{\"studies\":42}");
                }
            });
            server.start();
        }

        String getBaseUrl() {
            return baseUrl;
        }

        String getIssuer() {
            return baseUrl + "/realms/dcm4che";
        }

        String getBackendUrl() {
            return baseUrl + "/backend";
        }

        String getLastTokenRequest() {
            return lastTokenRequest;
        }

        String getLastBackendPath() {
            return lastBackendPath;
        }

        String getLastBackendAuthorization() {
            return lastBackendAuthorization;
        }

        String getLastRevokedToken() {
            return lastRevokedToken;
        }

        void stop() {
            server.stop(0);
        }

        /**
         * Replaces the response of the token endpoint for the given grant type.
         */
        void setTokenResponse(String grantType, String json) {
            tokenResponses.put(grantType, json);
        }

        /**
         * Builds a token endpoint response with an ID token for the given nonce.
         */
        String tokenResponse(String nonce, long expiresIn) {
            return tokenResponse(nonce, expiresIn, CLIENT_ID);
        }

        String tokenResponse(String nonce, long expiresIn, String audience) {
            long now = System.currentTimeMillis() / 1000L;
            String claims = "{\"iss\":" + Json.quote(getIssuer())
                    + ",\"sub\":" + Json.quote(SUBJECT)
                    + ",\"aud\":" + Json.quote(audience)
                    + ",\"azp\":" + Json.quote(CLIENT_ID)
                    + ",\"exp\":" + (now + 300)
                    + ",\"iat\":" + now
                    + ",\"preferred_username\":" + Json.quote(USERNAME)
                    + ",\"email\":\"jdoe@example.com\""
                    + ",\"realm_access\":{\"roles\":[\"dcm4che-user\"]}"
                    + (nonce != null ? ",\"nonce\":" + Json.quote(nonce) : "")
                    + "}";
            String idToken = "eyJhbGciOiJSUzI1NiJ9." + TokenSet.base64UrlEncode(Json.utf8(claims)) + ".signature";
            String accessToken = "eyJhbGciOiJSUzI1NiJ9."
                    + TokenSet.base64UrlEncode(Json.utf8("{\"sub\":" + Json.quote(SUBJECT) + ",\"iss\":"
                            + Json.quote(getIssuer()) + ",\"exp\":" + (now + 300) + "}"))
                    + ".signature";
            return "{\"access_token\":" + Json.quote(accessToken)
                    + ",\"refresh_token\":\"the-refresh-token\""
                    + ",\"token_type\":\"Bearer\""
                    + ",\"expires_in\":" + expiresIn
                    + ",\"scope\":\"openid profile email\""
                    + ",\"id_token\":" + Json.quote(idToken) + "}";
        }

        private void handleToken(HttpExchange exchange) throws IOException {
            lastTokenRequest = readBody(exchange);
            String grantType = formParameter(lastTokenRequest, "grant_type");
            String response = tokenResponses.get(grantType);
            if (response == null)
                response = tokenResponse(null, 300);
            respond(exchange, 200, response);
        }

        private String discoveryDocument() {
            return "{\"issuer\":" + Json.quote(getIssuer()) + ","
                    + "\"authorization_endpoint\":" + Json.quote(baseUrl
                            + "/realms/dcm4che/protocol/openid-connect/auth") + ","
                    + "\"token_endpoint\":" + Json.quote(baseUrl
                            + "/realms/dcm4che/protocol/openid-connect/token") + ","
                    + "\"end_session_endpoint\":" + Json.quote(baseUrl
                            + "/realms/dcm4che/protocol/openid-connect/logout") + ","
                    + "\"revocation_endpoint\":" + Json.quote(baseUrl
                            + "/realms/dcm4che/protocol/openid-connect/revoke") + ","
                    + "\"jwks_uri\":" + Json.quote(baseUrl + "/realms/dcm4che/certs") + ","
                    + "\"response_types_supported\":[\"code\"],"
                    + "\"grant_types_supported\":[\"authorization_code\",\"refresh_token\"]}";
        }

        private static void respond(HttpExchange exchange, int status, String body) throws IOException {
            byte[] bytes = Json.utf8(body);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, bytes.length);
            OutputStream out = exchange.getResponseBody();
            out.write(bytes);
            out.close();
        }

        private static String readBody(HttpExchange exchange) throws IOException {
            InputStream in = exchange.getRequestBody();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0)
                out.write(buf, 0, n);
            return new String(out.toByteArray(), Charset.forName("UTF-8"));
        }

        private static String formParameter(String form, String name) {
            if (form == null)
                return null;
            for (String pair : form.split("&")) {
                int i = pair.indexOf('=');
                if (i > 0 && pair.substring(0, i).equals(name))
                    return urlDecode(pair.substring(i + 1));
            }
            return null;
        }

        private static String urlDecode(String value) {
            try {
                return java.net.URLDecoder.decode(value, "UTF-8");
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    static List<String> list(String... values) {
        List<String> list = new ArrayList<String>();
        Collections.addAll(list, values);
        return list;
    }

    static void assertNoError(Response response) {
        assertEquals(200, response.getStatus());
    }
}
