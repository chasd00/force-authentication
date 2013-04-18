/*
 * Copyright, 2013, SALESFORCE.com
 * All Rights Reserved
 * Company Confidential
 */
package net.davidbuccola.force.authentication;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Component("oAuthFilter")
public class OAuthFilter extends GenericFilterBean {
    public static final String CALLBACK_PATH = "/_oauth";

    private static final List<GrantedAuthority> AUTHORITIES = Arrays.asList(
        (GrantedAuthority) new SimpleGrantedAuthority("ROLE_USER"),
        (GrantedAuthority) new SimpleGrantedAuthority("ROLE_API_USER"));

    @Autowired
    private OAuthConnector connector;

    @Override
    @edu.umd.cs.findbugs.annotations.SuppressWarnings("HRS_REQUEST_PARAMETER_TO_HTTP_HEADER") //TODO Fix!
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        final HttpServletRequest request = (HttpServletRequest) req;
        final HttpServletResponse response = (HttpServletResponse) res;

        if (isOAuthCallback(request)) {
            if (isSuccessCallback(request)) {

                logger.debug("OAuth success callback, requesting token");
                ForceAuthenticationToken authenticationToken =
                    connector.getToken(request.getParameter("code"), request.getRequestURL().toString());

                SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                String redirectUri = request.getParameter("state");
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format(
                        "OAuth authentication successful, redirecting to: %s", redirectUri));
                }
                response.sendRedirect(redirectUri);
                return;

            } else if (isErrorCallback(request)) {

                String message = extractErrorMessage(request);
                if (logger.isDebugEnabled()) {
                    logger.debug("OAuth error callback: " + message);
                }
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
                return;

            } else {

                String message = "OAuth callback is missing required parameters";
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("Invalid OAuth callback: %s: %s", message, getRequestUriWithQueryString(request)));
                }
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, message);
                return;
            }
        } else if (isHeaderBasedAuthentication(request)) {

            String accessToken = request.getHeader("Authorization").split("\\s+", 2)[1];
            String instanceUrl = request.getHeader("Force-Instance-Url");
            String userId = request.getHeader("Force-User-Id");

            if (areAllAuthenticationHeadersSpecified(userId, accessToken, instanceUrl)) {

                ForceAuthenticationToken authenticationToken =
                    new ForceAuthenticationToken(userId, accessToken, instanceUrl, AUTHORITIES);
                authenticationToken.setAuthenticated(true);
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                if (logger.isDebugEnabled()) {
                    logger.debug(String.format(
                        "Header-based authentication established: userId=%s, accessToken=%s, instanceUrl=%s",
                        userId, accessToken, instanceUrl));
                }

            } else {
                String message = "Header-based authentication is missing required values";
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format(
                        "%s: userId=%s, accessToken=%s, instanceUrl=%s",
                        message, userId, accessToken, instanceUrl));
                }
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, message);
                return;
            }
        }

        chain.doFilter(request, response);
    }

    private static boolean isOAuthCallback(HttpServletRequest request) {
        return CALLBACK_PATH.equals(request.getServletPath());
    }

    private static boolean isSuccessCallback(ServletRequest request) {
        return StringUtils.defaultIfEmpty(request.getParameter("code"), null) != null;
    }

    private static boolean isErrorCallback(ServletRequest request) {
        return StringUtils.defaultIfEmpty(request.getParameter("error"), null) != null;
    }

    private static String extractErrorMessage(HttpServletRequest request) {
        return StringUtils.defaultIfEmpty(request.getParameter("error"), "Authorization failed")
            + ":" + StringUtils.defaultIfEmpty(request.getParameter("error_description"), "");
    }

    private static String getRequestUriWithQueryString(HttpServletRequest request) {
        if (request.getQueryString() != null) {
            StringBuilder builder = new StringBuilder(request.getRequestURI());
            builder.append("?").append(request.getQueryString());
            return builder.toString();
        } else {
            return request.getRequestURI();
        }
    }

    private static boolean isHeaderBasedAuthentication(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        return authorization != null && authorization.substring(0, 6).equalsIgnoreCase("OAuth ");
    }

    private static boolean areAllAuthenticationHeadersSpecified(String userId, String accessToken, String instanceUrl) {
        return StringUtils.isNotEmpty(userId) && StringUtils.isNotEmpty(accessToken) && StringUtils.isNotEmpty(instanceUrl);
    }
}
