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
import java.util.Enumeration;
import java.util.Properties;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Bootstraps the BFF from the servlet context, reading the configuration from
 * <code>/WEB-INF/bff.properties</code> and creating the {@link BffServlet} and the
 * {@link BffProxyServlet} that delegate to it.
 * <p>
 * Any init parameter whose name starts with <code>bff.</code> overrides the
 * corresponding entry of the properties file, so a deployment can be configured
 * without repackaging the archive.
 *
 * @author dcm4che
 */
public class BffBootstrapServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final Logger LOG = LoggerFactory.getLogger(BffBootstrapServlet.class);

    public static final String CONFIG_RESOURCE = "bff.properties";

    public static final String BFF_SERVLET_ATTRIBUTE = "org.dcm4che3.bff.servlet";
    public static final String PROXY_SERVLET_ATTRIBUTE = "org.dcm4che3.bff.proxy";

    private final BffServlet bff;
    private final BffProxyServlet proxy;

    public BffBootstrapServlet() {
        this(null);
    }

    BffBootstrapServlet(BffConfiguration configuration) {
        if (configuration != null) {
            this.bff = createBffServlet(configuration);
            this.proxy = new BffProxyServlet(bff);
        } else {
            this.bff = null;
            this.proxy = null;
        }
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        if (bff != null)
            return;
        BffConfiguration configuration;
        try {
            configuration = loadConfiguration(config);
        } catch (IOException e) {
            throw new ServletException("Failed to load " + CONFIG_RESOURCE, e);
        }
        LOG.info("Initializing BFF: {}", configuration);
        BffServlet servlet = createBffServlet(configuration);
        config.getServletContext().setAttribute(BFF_SERVLET_ATTRIBUTE, servlet);
        config.getServletContext().setAttribute(PROXY_SERVLET_ATTRIBUTE, new BffProxyServlet(servlet));
    }

    /**
     * Reads the configuration, applying the init parameters as overrides.
     */
    static BffConfiguration loadConfiguration(ServletConfig config) throws IOException {
        Properties props = new Properties();
        java.io.InputStream in = config.getServletContext().getResourceAsStream("/WEB-INF/" + CONFIG_RESOURCE);
        if (in != null)
            try {
                props.load(in);
            } finally {
                in.close();
            }
        for (Enumeration<String> e = config.getInitParameterNames(); e != null && e.hasMoreElements();) {
            String name = e.nextElement();
            if (name.startsWith("bff."))
                props.setProperty(name, config.getInitParameter(name));
        }
        return BffConfiguration.fromProperties(props);
    }

    private static BffServlet createBffServlet(BffConfiguration configuration) {
        try {
            OpenIdClient client = OpenIdClient.create(configuration);
            return new BffServlet(configuration, client);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load OpenID Connect provider metadata from "
                    + configuration.getDiscoveryUri(), e);
        }
    }

    /**
     * Delegates to the BFF servlet, so that a single servlet mapping
     * (<code>/bff/*</code>) serves the endpoints and, for any other path, the
     * authenticated proxy to the backend.
     */
    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        BffServlet servlet = bff();
        String path = req.getPathInfo();
        if (path == null || path.isEmpty() || path.equals("/") || isBffEndpoint(path))
            servlet.service(req, resp);
        else
            proxy().service(req, resp);
    }

    private static boolean isBffEndpoint(String path) {
        return path.startsWith("/login") || path.startsWith("/callback") || path.startsWith("/userinfo")
                || path.startsWith("/status") || path.startsWith("/logout");
    }

    private BffServlet bff() throws ServletException {
        if (bff != null)
            return bff;
        Object attribute = getServletConfig().getServletContext().getAttribute(BFF_SERVLET_ATTRIBUTE);
        if (attribute instanceof BffServlet)
            return (BffServlet) attribute;
        throw new ServletException("BFF not initialized");
    }

    private BffProxyServlet proxy() throws ServletException {
        if (proxy != null)
            return proxy;
        Object attribute = getServletConfig().getServletContext().getAttribute(PROXY_SERVLET_ATTRIBUTE);
        if (attribute instanceof BffProxyServlet)
            return (BffProxyServlet) attribute;
        throw new ServletException("BFF proxy not initialized");
    }

    static void writeJson(HttpServletResponse resp, String json) throws IOException {
        resp.setStatus(HttpServletResponse.SC_OK);
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        PrintWriter writer = resp.getWriter();
        writer.write(json);
        writer.flush();
    }
}
