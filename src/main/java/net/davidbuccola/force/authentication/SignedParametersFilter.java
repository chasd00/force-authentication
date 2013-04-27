/*
 * Copyright, 2013, SALESFORCE.com
 * All Rights Reserved
 * Company Confidential
 */
package net.davidbuccola.force.authentication;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
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
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * A security filter that looks for authentication information in the form of signed query parameters on the HTTP
 * request.
 */
@Component("signedParametersFilter")
public class SignedParametersFilter extends GenericFilterBean {

    private static final List<GrantedAuthority> AUTHORITIES = Arrays.asList(
        (GrantedAuthority) new SimpleGrantedAuthority("ROLE_USER"),         // Indicate user is authenticated
        (GrantedAuthority) new SimpleGrantedAuthority("ROLE_API_USER"),     // Indicate user can access the API
        (GrantedAuthority) new SimpleGrantedAuthority("ROLE_CANVAS_USER")); // Indicate user came through an SFDC canvas

    @Autowired
    private OAuthClientConfig clientConfig;

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        final HttpServletRequest request = (HttpServletRequest) req;
        final HttpServletResponse response = (HttpServletResponse) res;

        String signedParameters = request.getParameter(SignedRequestFilter.SIGNED_PARAMETERS);
        if (signedParameters != null) {

            if (logger.isDebugEnabled()) {
                logger.debug(String.format("Canvas '%s' detected", SignedRequestFilter.SIGNED_PARAMETERS));
            }

            Map<String, String> parameters;
            try {
                parameters = SignedParametersUtil.verifyAndDecode(signedParameters, clientConfig.getClientSecret());
            } catch (GeneralSecurityException e) {
                String message = "Signed parameters decode and verify failed";
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("%s: signed_parameters=%s", message, signedParameters), e);
                }
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, message);
                return;
            }

            String userId = StringUtils.defaultIfEmpty(parameters.remove("userId"), null);
            String accessToken = StringUtils.defaultIfEmpty(parameters.remove("accessToken"), null);
            String instanceUrl = StringUtils.defaultIfEmpty(parameters.remove("instanceUrl"), null);
            if (isAnyAuthenticationParameterSpecified(userId, accessToken, instanceUrl)) {
                if (areAllAuthenticationParametersSpecified(userId, accessToken, instanceUrl)) {

                    ForceAuthenticationToken authenticationToken =
                        new ForceAuthenticationToken(userId, accessToken, instanceUrl, AUTHORITIES);
                    authenticationToken.setAuthenticated(true);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                    if (logger.isDebugEnabled()) {
                        logger.debug(String.format(
                            "Signed parameters authentication established: userId=%s, accessToken=%s, instanceUrl=%s",
                            userId, accessToken, instanceUrl));
                    }
                } else if (isJustUserIdSpecified(userId, accessToken, instanceUrl)) {

                    String currentUserId = getCurrentSecurityContextUserId();
                    if (currentUserId != null && !currentUserId.equals(userId)) {
                        SecurityContextHolder.clearContext();

                        if (logger.isDebugEnabled()) {
                            logger.debug(String.format(
                                "Cleared security context because userId does not match. Old userId=%s, New userId=%s",
                                currentUserId, userId));
                        }
                    }
                } else {

                    String message = "Signed parameters authentication is missing required values";
                    if (logger.isDebugEnabled()) {
                        logger.debug(String.format(
                            "%s: userId=%s, accessToken=%s, instanceUrl=%s",
                            message, userId, accessToken, instanceUrl));
                    }
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST, message);
                    return;
                }
            }

            request.setAttribute(SignedRequestFilter.SIGNED_PARAMETERS, signedParameters);
        }

        chain.doFilter(request, response);
    }

    private static boolean isAnyAuthenticationParameterSpecified(String userId, String accessToken, String instanceUrl) {
        return userId != null || accessToken != null || instanceUrl != null;
    }

    private static boolean areAllAuthenticationParametersSpecified(String userId, String accessToken, String instanceUrl) {
        return userId != null && accessToken != null && instanceUrl != null;
    }

    private static boolean isJustUserIdSpecified(String userId, String accessToken, String instanceUrl) {
        return userId != null && accessToken == null && instanceUrl == null;
    }

    private static String getCurrentSecurityContextUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication instanceof ForceAuthenticationToken) {
            return ((ForceAuthenticationToken) authentication).getUserId();
        } else {
            return null;
        }
    }
}
