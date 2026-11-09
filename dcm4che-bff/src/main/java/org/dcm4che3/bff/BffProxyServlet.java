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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Proxies requests from the browser to the protected backend, attaching the
 * access token of the BFF session as a <code>Bearer</code> credential.
 * <p>
 * The browser never sees the token and never talks to the backend directly, so
 * the backend can be locked down to accept requests from the BFF only. Requests
 * without a valid session are answered with <code>401</code>, which the frontend
 * uses to redirect the user to <code>/bff/login</code>.
 * <p>
 * Hop-by-hop headers, and any header carrying a credential supplied by the
 * browser, are removed from the forwarded request.
 *
 * @author dcm4che
 */
public class BffProxyServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final Logger LOG = LoggerFactory.getLogger(BffProxyServlet.class);

    private static final Set<String> HOP_BY_HOP;
    private static final Set<String> STRIPPED_REQUEST_HEADERS;
    private static final Set<String> STRIPPED_RESPONSE_HEADERS;

    static {
        Set<String> hop = new HashSet<String>();
        Collections.addAll(hop, "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length");
        HOP_BY_HOP = Collections.unmodifiableSet(hop);

        Set<String> request = new HashSet<String>(hop);
        // never let the browser inject credentials or forge the client identity
        Collections.addAll(request, "authorization", "cookie", "x-forwarded-for", "x-forwarded-host",
                "x-forwarded-proto", "x-real-ip");
        STRIPPED_REQUEST_HEADERS = Collections.unmodifiableSet(request);

        Set<String> response = new HashSet<String>(hop);
        Collections.addAll(response, "set-cookie", "www-authenticate");
        STRIPPED_RESPONSE_HEADERS = Collections.unmodifiableSet(response);
    }

    private final BffServlet bff;

    public BffProxyServlet(BffServlet bff) {
        this.bff = bff;
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String backendUri = bff.getConfiguration().getBackendUri();
        if (backendUri == null) {
            BffServlet.sendError(resp, HttpServletResponse.SC_NOT_IMPLEMENTED, "No backend configured");
            return;
        }
        TokenSet tokens = bff.authenticate(req);
        if (tokens == null) {
            resp.setHeader("Cache-Control", "no-store");
            BffServlet.sendError(resp, HttpServletResponse.SC_UNAUTHORIZED, "Not authenticated");
            return;
        }
        forward(req, resp, backendUri, tokens);
    }

    private void forward(HttpServletRequest req, HttpServletResponse resp, String backendUri, TokenSet tokens)
            throws IOException {
        String query = req.getQueryString();
        String target = backendUri + pathInfo(req) + (query != null ? "?" + query : "");
        byte[] body = readBody(req);
        HttpURLConnection conn = (HttpURLConnection) new URL(target).openConnection();
        try {
            conn.setRequestMethod(req.getMethod());
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(60000);
            conn.setInstanceFollowRedirects(false);
            conn.setDoInput(true);
            copyRequestHeaders(req, conn);
            conn.setRequestProperty("Authorization", "Bearer " + tokens.getAccessToken());
            if (body.length > 0 || hasBody(req.getMethod())) {
                conn.setDoOutput(true);
                if (body.length > 0)
                    conn.setFixedLengthStreamingMode(body.length);
                OutputStream out = conn.getOutputStream();
                out.write(body);
                out.flush();
                out.close();
            }
            int status = conn.getResponseCode();
            resp.setStatus(status);
            copyResponseHeaders(conn, resp);
            InputStream in = status >= 400 ? conn.getErrorStream() : conn.getInputStream();
            if (in != null) {
                OutputStream out = resp.getOutputStream();
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0)
                    out.write(buf, 0, n);
                out.flush();
            }
        } catch (IOException e) {
            LOG.warn("Forwarding {} {} to backend failed", req.getMethod(), target, e);
            BffServlet.sendError(resp, HttpServletResponse.SC_BAD_GATEWAY, "Backend unavailable");
        } finally {
            conn.disconnect();
        }
    }

    private static boolean hasBody(String method) {
        return !("GET".equals(method) || "HEAD".equals(method) || "DELETE".equals(method));
    }

    private static String pathInfo(HttpServletRequest req) {
        String path = req.getPathInfo();
        return path != null ? path : "";
    }

    private static byte[] readBody(HttpServletRequest req) throws IOException {
        InputStream in = req.getInputStream();
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0)
            out.write(buf, 0, n);
        return out.toByteArray();
    }

    private static void copyRequestHeaders(HttpServletRequest req, HttpURLConnection conn) {
        List<String> names = new ArrayList<String>();
        for (Enumeration<String> e = req.getHeaderNames(); e != null && e.hasMoreElements();)
            names.add(e.nextElement());
        for (String name : names) {
            if (STRIPPED_REQUEST_HEADERS.contains(name.toLowerCase()))
                continue;
            for (Enumeration<String> values = req.getHeaders(name); values.hasMoreElements();)
                conn.addRequestProperty(name, values.nextElement());
        }
    }

    private static void copyResponseHeaders(HttpURLConnection conn, HttpServletResponse resp) {
        for (String name : conn.getHeaderFields().keySet()) {
            if (name == null || STRIPPED_RESPONSE_HEADERS.contains(name.toLowerCase()))
                continue;
            for (String value : conn.getHeaderFields().get(name))
                resp.addHeader(name, value);
        }
    }
}
