/*
 * Copyright, 2013, SALESFORCE.com
 * All Rights Reserved
 * Company Confidential
 */
package net.davidbuccola.force.authentication;

import canvas.CanvasRequest;
import canvas.SignedRequest;
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
import java.util.Map;

/**
 * A security filter that looks for authentication information in the form of a Salesforce canvas signed request passed
 * as a query parameter.
 */
@Component("signedRequestFilter")
public class SignedRequestFilter extends GenericFilterBean {
    public static final String SIGNED_PARAMETERS = "signed_parameters";
    public static final String SIGNED_REQUEST = "signed_request";

    private static final List<GrantedAuthority> AUTHORITIES = Arrays.asList(
        (GrantedAuthority) new SimpleGrantedAuthority("ROLE_USER"),
        (GrantedAuthority) new SimpleGrantedAuthority("ROLE_CANVAS_USER"));

    @Autowired
    private OAuthClientConfig clientConfig;

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        final HttpServletRequest request = (HttpServletRequest) req;
        final HttpServletResponse response = (HttpServletResponse) res;

        String signedRequest = request.getParameter(SIGNED_REQUEST);
        if (signedRequest != null) {

            if (logger.isDebugEnabled()) {
                logger.debug(String.format("Canvas '%s' detected", SIGNED_REQUEST));
            }

            CanvasRequest canvasRequest;
            try {
                canvasRequest = SignedRequest.verifyAndDecode(signedRequest, clientConfig.getClientSecret());
            } catch (SecurityException e) {
                String message = "Signed request verification failed";
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("%s: signed_request=%s", message, signedRequest), e);
                }
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, message);
                return;
            }

            ForceAuthenticationToken authenticationToken =
                new ForceAuthenticationToken(
                    canvasRequest.getContext().getUserContext().getUserId(),
                    canvasRequest.getClient().getOAuthToken(),
                    canvasRequest.getClient().getInstanceUrl(),
                    AUTHORITIES);
            authenticationToken.setAuthenticated(true);
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            Map<String, Object> signedParameters = canvasRequest.getContext().getEnvironmentContext().getParameters();
            request.setAttribute(SIGNED_PARAMETERS, signedParameters);

            if (logger.isDebugEnabled()) {
                logger.debug(String.format(
                    "Signed request authentication successful: %s",
                    SignedRequest.verifyAndDecodeAsJson(signedRequest, clientConfig.getClientSecret())));
            }
        }

        chain.doFilter(request, response);
    }
}
