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

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Reads and writes the session cookie of the BFF.
 * <p>
 * The cookie only carries the session identifier. It is <code>HttpOnly</code> so
 * that JavaScript running in the browser cannot read it, <code>Secure</code> by
 * default so that it is never sent over plain HTTP, <code>SameSite=Lax</code> so
 * that it is not attached to cross site requests, and scoped to the path of the
 * BFF, so it does not leak to the rest of the application.
 *
 * @author dcm4che
 */
public class SessionCookie {

    private static final String SAME_SITE = "SameSite=Lax";

    private final String name;
    private final boolean secure;
    private final String path;

    public SessionCookie(BffConfiguration configuration) {
        this(configuration.getCookieName(), configuration.isCookieSecure(), "/bff");
    }

    public SessionCookie(String name, boolean secure, String path) {
        this.name = name;
        this.secure = secure;
        this.path = path;
    }

    public String getName() {
        return name;
    }

    public String getPath() {
        return path;
    }

    /**
     * Returns the session identifier carried by the request, or <code>null</code>.
     */
    public String read(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null)
            return null;
        for (Cookie cookie : cookies)
            if (name.equals(cookie.getName()))
                return cookie.getValue();
        return null;
    }

    /**
     * Adds the Set-Cookie header that stores the session identifier in the browser.
     */
    public void write(HttpServletResponse response, String sessionId, int maxAgeSeconds) {
        response.addHeader("Set-Cookie", header(sessionId, maxAgeSeconds));
    }

    /**
     * Adds the Set-Cookie header that removes the session cookie from the browser.
     */
    public void clear(HttpServletResponse response) {
        response.addHeader("Set-Cookie", header("", 0));
    }

    /**
     * Builds the value of the Set-Cookie header.
     */
    public String header(String value, int maxAgeSeconds) {
        List<String> parts = new ArrayList<String>();
        parts.add(name + "=" + value);
        parts.add("Path=" + path);
        parts.add("Max-Age=" + Math.max(0, maxAgeSeconds));
        parts.add("HttpOnly");
        parts.add(SAME_SITE);
        if (secure)
            parts.add("Secure");
        return join(parts);
    }

    private static String join(List<String> parts) {
        StringBuilder sb = new StringBuilder();
        for (String part : parts) {
            if (sb.length() > 0)
                sb.append("; ");
            sb.append(part);
        }
        return sb.toString();
    }
}
