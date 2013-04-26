/*
 * Copyright, 2013, SALESFORCE.com
 * All Rights Reserved
 * Company Confidential
 */
package net.davidbuccola.force.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;

@Component("authenticationEntryPoint")
public class OAuthAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private static final FilterChain nullFilterChain = new NullFilterChain();

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Autowired
    private OAuthConnector connector;

    @Autowired
    private FilterSecurityInterceptor filterSecurityInterceptor;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        if (isApiUrl(request, response)) {
            if (log.isDebugEnabled()) {
                log.debug("Rejecting unauthorized access to API URI: " + request.getRequestURI());
            }
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage());
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Initiating OAuth exchange to gain access to URI: " + request.getRequestURI());
            }
            response.sendRedirect(connector.buildAuthorizeUri(buildCallbackUrl(request), buildFinalRedirectUrl(request)));
        }
    }

    /**
     * See if the request URL is for an API endpoint. API endpoints are identified by including "ROLE_API_USER" in
     * the access list of Spring "intercept-url" definitions.
     */
    private boolean isApiUrl(HttpServletRequest request, HttpServletResponse response) {
        FilterInvocation fauxFilterInvocation = new FilterInvocation(request, response, nullFilterChain);
        Collection<ConfigAttribute> attributes = filterSecurityInterceptor.getSecurityMetadataSource().getAttributes(fauxFilterInvocation);
        for (ConfigAttribute attribute : attributes) {
            if (attribute.toString().contains("ROLE_API_USER")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Build the OAuth callback URL which will come back to us and get caught by the OAuthFilter.
     */
    private static String buildCallbackUrl(HttpServletRequest request) {
        StringBuilder builder = new StringBuilder();
        final String scheme = request.getScheme();
        int port = request.getServerPort();
        if (port < 0)
            port = 80; // Work around java.net.URL bug

        builder.append(scheme).append("://");
        builder.append(request.getServerName());
        if ((scheme.equals("http") && (port != 80)) || (scheme.equals("https") && (port != 443))) {
            builder.append(':').append(port);
        }

        builder.append(request.getContextPath());
        builder.append("/_oauth");

        return builder.toString();
    }

    /**
     * Build the final redirect URL that will be used when the OAuth process is successfully completed. This is the URL
     * of the current request. In other words, we return to this URL after net.davidbuccola.net.davidbuccola.force.authentication has been achieved.
     */
    private static String buildFinalRedirectUrl(HttpServletRequest request) {
        StringBuffer buffer = request.getRequestURL();
        if (request.getQueryString() != null) {
            buffer.append("?").append(request.getQueryString());
        }
        return buffer.toString();
    }

    /**
     * A null filter chain for use in creating faux filter invocations.
     */
    private static class NullFilterChain implements FilterChain {
        @Override
        public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
        }
    }
}
