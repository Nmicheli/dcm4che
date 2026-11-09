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

/**
 * Server side state of an authenticated browser session.
 * <p>
 * Besides the tokens, the pending authorization request (state, nonce and PKCE
 * code verifier) is kept here, so that the callback of the provider can be
 * validated against the session that started the login. That is what makes the
 * BFF resistant to login CSRF and to authorization code injection.
 *
 * @author dcm4che
 */
public class BffSession {

    private final String id;
    private final long createdAt;
    private volatile long lastAccess;
    private volatile String state;
    private volatile String nonce;
    private volatile String codeVerifier;
    private volatile String redirectUri;
    private volatile TokenSet tokens;

    public BffSession(String id, long now) {
        this.id = id;
        this.createdAt = now;
        this.lastAccess = now;
    }

    public String getId() {
        return id;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public long getLastAccess() {
        return lastAccess;
    }

    void touch(long now) {
        this.lastAccess = now;
    }

    /**
     * Starts a new authorization request on this session, discarding any previous one.
     */
    public void startAuthorization(String state, String nonce, String codeVerifier, String redirectUri) {
        this.state = state;
        this.nonce = nonce;
        this.codeVerifier = codeVerifier;
        this.redirectUri = redirectUri;
    }

    public String getState() {
        return state;
    }

    public String getNonce() {
        return nonce;
    }

    public String getCodeVerifier() {
        return codeVerifier;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public boolean isAuthenticated() {
        return tokens != null;
    }

    public TokenSet getTokens() {
        return tokens;
    }

    public void setTokens(TokenSet tokens) {
        this.tokens = tokens;
        // the authorization request is single use
        this.state = null;
        this.nonce = null;
        this.codeVerifier = null;
    }

    public void clear() {
        this.tokens = null;
        this.state = null;
        this.nonce = null;
        this.codeVerifier = null;
    }

    /**
     * Checks whether the session is expired, either because it exceeded its
     * absolute lifetime or because it was idle for too long.
     */
    public boolean isExpired(long now, int idleTimeoutSeconds) {
        return now - lastAccess > idleTimeoutSeconds * 1000L;
    }

    @Override
    public String toString() {
        return "BffSession[id=" + id + ", authenticated=" + isAuthenticated() + "]";
    }
}
