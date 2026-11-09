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
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Backend for Frontend of a dcm4che web application, authenticating users with
 * Keycloak (or any other OpenID Connect provider).
 * <p>
 * The BFF implements the Authorization Code flow with PKCE entirely on the
 * server. The browser only ever holds an opaque, <code>HttpOnly</code> session
 * cookie; access, refresh and ID tokens are stored in a server side
 * {@link BffSessionStore} and are never exposed to JavaScript. Requests to the
 * protected backend are proxied by {@link BffProxyServlet}, which attaches the
 * access token before forwarding them.
 * <p>
 * Endpoints, relative to the servlet mapping (<code>/bff/*</code>):
 * <ul>
 * <li><code>GET /bff/login</code> - starts the login, redirecting to the provider
 *     (optional parameter <code>redirect</code>, must be an allowed URI)</li>
 * <li><code>GET /bff/callback</code> - the redirect URI registered for the client;
 *     validates state and nonce, exchanges the code and creates the session</li>
 * <li><code>GET /bff/userinfo</code> - the authenticated user, as JSON</li>
 * <li><code>GET /bff/status</code> - whether a session exists, as JSON</li>
 * <li><code>POST /bff/logout</code> - ends the session, revoking the tokens;
 *     answers with JSON containing the provider logout URL, if any</li>
 * </ul>
 *
 * @author dcm4che
 */
public class BffServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final Logger LOG = LoggerFactory.getLogger(BffServlet.class);

    /** Request attribute holding the authenticated session, set by this servlet and by the proxy. */
    public static final String SESSION_ATTRIBUTE = "org.dcm4che3.bff.session";

    /** Request attribute holding the validated token set. */
    public static final String TOKENS_ATTRIBUTE = "org.dcm4che3.bff.tokens";

    private final BffConfiguration configuration;
    private final BffSessionStore sessions;
    private final SessionCookie cookie;
    private final OpenIdClient client;
    private final TokenValidator validator;

    public BffServlet(BffConfiguration configuration, OpenIdClient client) {
        this(configuration, client, new BffSessionStore(configuration.getSessionTimeout()));
    }

    public BffServlet(BffConfiguration configuration, OpenIdClient client, BffSessionStore sessions) {
        this.configuration = configuration;
        this.client = client;
        this.sessions = sessions;
        this.cookie = new SessionCookie(configuration);
        this.validator = new TokenValidator(configuration, client.getMetadata());
    }

    public BffConfiguration getConfiguration() {
        return configuration;
    }

    public BffSessionStore getSessionStore() {
        return sessions;
    }

    public OpenIdClient getClient() {
        return client;
    }

    public SessionCookie getSessionCookie() {
        return cookie;
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String command = command(req);
        try {
            if (command.equals("login"))
                login(req, resp);
            else if (command.equals("callback"))
                callback(req, resp);
            else if (command.equals("userinfo"))
                userinfo(req, resp);
            else if (command.equals("status"))
                status(req, resp);
            else if (command.equals("logout"))
                logout(req, resp);
            else
                sendError(resp, HttpServletResponse.SC_NOT_FOUND, "Unknown BFF endpoint: " + command);
        } catch (TokenValidator.TokenValidationException e) {
            LOG.warn("Rejected token: {}", e.getMessage());
            endSession(req, resp, false);
            sendError(resp, HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
        } catch (IOException e) {
            LOG.error("BFF request to {} failed", command, e);
            sendError(resp, HttpServletResponse.SC_BAD_GATEWAY, "OpenID Connect provider unavailable");
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String command = command(req);
        if (command.equals("logout"))
            logout(req, resp);
        else
            sendError(resp, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "POST not supported for " + command);
    }

    /**
     * Starts the login: creates a session if needed, stores state, nonce and the
     * PKCE code verifier, and redirects the browser to the authorization endpoint.
     */
    void login(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String redirect = req.getParameter("redirect");
        if (redirect != null && !configuration.isAllowedRedirectUri(redirect)) {
            sendError(resp, HttpServletResponse.SC_BAD_REQUEST, "Redirect target not allowed");
            return;
        }
        BffSession session = getOrCreateSession(req);
        String state = TokenSet.randomToken(32);
        String nonce = TokenSet.randomToken(16);
        String codeVerifier = TokenSet.randomToken(48);
        String redirectUri = redirect != null ? redirect : configuration.getRedirectUri();
        session.startAuthorization(state, nonce, codeVerifier, redirectUri);
        cookie.write(resp, session.getId(), configuration.getSessionTimeout());
        resp.sendRedirect(client.getAuthorizationUrl(state, TokenSet.codeChallenge(codeVerifier), nonce));
    }

    /**
     * Handles the redirect back from the provider.
     */
    void callback(HttpServletRequest req, HttpServletResponse resp) throws IOException,
            TokenValidator.TokenValidationException {
        String error = req.getParameter("error");
        if (error != null) {
            LOG.info("Provider returned error {}: {}", error, req.getParameter("error_description"));
            endSession(req, resp, false);
            sendError(resp, HttpServletResponse.SC_UNAUTHORIZED, "Login failed: " + error);
            return;
        }
        String code = req.getParameter("code");
        String state = req.getParameter("state");
        if (code == null || state == null) {
            sendError(resp, HttpServletResponse.SC_BAD_REQUEST, "Missing authorization code or state");
            return;
        }
        BffSession session = sessions.get(cookie.read(req));
        if (session == null) {
            sendError(resp, HttpServletResponse.SC_UNAUTHORIZED, "No pending login for this browser");
            return;
        }
        String expectedState = session.getState();
        String codeVerifier = session.getCodeVerifier();
        if (!TokenValidator.equalsConstantTime(expectedState, state) || codeVerifier == null) {
            LOG.warn("Authorization response with unexpected state");
            endSession(req, resp, false);
            sendError(resp, HttpServletResponse.SC_UNAUTHORIZED, "Invalid state in authorization response");
            return;
        }
        TokenSet tokens = client.exchangeCode(code, codeVerifier);
        // the nonce is only checked when the provider echoes it in the ID token
        String expectedNonce = tokens.getClaims().containsKey("nonce") ? session.getNonce() : null;
        validator.validateIdToken(tokens.getClaims(), expectedNonce, System.currentTimeMillis());
        String target = session.getRedirectUri();
        session.setTokens(tokens);
        cookie.write(resp, session.getId(), configuration.getSessionTimeout());
        LOG.info("BFF session {} authenticated as {}", session.getId(), tokens.getPreferredUsername());
        resp.sendRedirect(target != null ? target : "/");
    }

    void userinfo(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        TokenSet tokens = authenticate(req);
        if (tokens == null) {
            sendError(resp, HttpServletResponse.SC_UNAUTHORIZED, "Not authenticated");
            return;
        }
        sendJson(resp, Json.write(TokenValidator.userInfo(tokens)));
    }

    void status(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        BffSession session = session(req);
        StringBuilder sb = new StringBuilder("{\"authenticated\":");
        sb.append(session != null && session.isAuthenticated());
        if (session != null && session.isAuthenticated()) {
            TokenSet tokens = session.getTokens();
            sb.append(",\"username\":").append(Json.quote(tokens.getPreferredUsername()));
            sb.append(",\"expiresIn\":").append(tokens.getExpiresIn(System.currentTimeMillis()));
        }
        sb.append('}');
        sendJson(resp, sb.toString());
    }

    void logout(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        BffSession session = session(req);
        String logoutUrl = null;
        if (session != null && session.getTokens() != null) {
            TokenSet tokens = session.getTokens();
            client.revoke(tokens.getRefreshToken(), "refresh_token");
            logoutUrl = client.getLogoutUrl(tokens.getIdToken());
        }
        endSession(req, resp, false);
        if (logoutUrl != null)
            sendJson(resp, "{\"logoutUrl\":" + Json.quote(logoutUrl) + "}");
        else
            sendJson(resp, "{\"logoutUrl\":null}");
    }

    /**
     * Returns the token set of the authenticated session, refreshing it if the
     * access token is about to expire; returns <code>null</code> if the request is
     * not authenticated.
     */
    TokenSet authenticate(HttpServletRequest req) throws IOException {
        BffSession session = session(req);
        if (session == null || !session.isAuthenticated())
            return null;
        TokenSet tokens = session.getTokens();
        long now = System.currentTimeMillis();
        // refresh when less than 30 seconds of validity are left
        if (tokens.getExpiresAt() > 0 && tokens.getExpiresAt() - now < 30000) {
            String refreshToken = tokens.getRefreshToken();
            if (refreshToken == null) {
                session.clear();
                return null;
            }
            try {
                TokenSet refreshed = client.refresh(refreshToken);
                session.setTokens(refreshed);
                req.setAttribute(TOKENS_ATTRIBUTE, refreshed);
                return refreshed;
            } catch (Json.HttpStatusException e) {
                LOG.info("Refresh of access token failed with status {}", e.getStatus());
                session.clear();
                return null;
            }
        }
        req.setAttribute(TOKENS_ATTRIBUTE, tokens);
        return tokens;
    }

    BffSession session(HttpServletRequest req) {
        BffSession session = sessions.get(cookie.read(req));
        if (session != null)
            req.setAttribute(SESSION_ATTRIBUTE, session);
        return session;
    }

    private BffSession getOrCreateSession(HttpServletRequest req) {
        BffSession session = session(req);
        return session != null ? session : sessions.create();
    }

    private void endSession(HttpServletRequest req, HttpServletResponse resp, boolean redirect) {
        String id = cookie.read(req);
        BffSession session = id != null ? sessions.peek(id) : null;
        if (session != null)
            session.clear();
        sessions.remove(id);
        req.removeAttribute(SESSION_ATTRIBUTE);
        req.removeAttribute(TOKENS_ATTRIBUTE);
        cookie.clear(resp);
    }

    private static String command(HttpServletRequest req) {
        String path = req.getPathInfo();
        if (path == null || path.isEmpty() || path.equals("/"))
            return "status";
        return path.startsWith("/") ? path.substring(1) : path;
    }

    static void sendJson(HttpServletResponse resp, String json) throws IOException {
        resp.setStatus(HttpServletResponse.SC_OK);
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        resp.setHeader("Cache-Control", "no-store");
        PrintWriter writer = resp.getWriter();
        writer.write(json);
        writer.flush();
    }

    static void sendError(HttpServletResponse resp, int status, String message) throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        resp.setHeader("Cache-Control", "no-store");
        PrintWriter writer = resp.getWriter();
        writer.write("{\"error\":" + Json.quote(message) + "}");
        writer.flush();
    }
}
