/*
 * Copyright, 2013, SALESFORCE.com
 * All Rights Reserved
 * Company Confidential
 */
package net.davidbuccola.force.authentication;

import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Utilities for working the authentication context.
 */
public final class AuthenticationUtils {
    private AuthenticationUtils() {
        throw new UnsupportedOperationException("Can not be instantiated");
    }

    /**
     * Gets the current Salesforce authentication information.
     *
     * @return the current authentication information
     * @throws InsufficientAuthenticationException
     *          if no Salesforce authentication information exists in the current security context.
     */
    public static ForceAuthenticationToken getAuthenticationToken() {
        ForceAuthenticationToken authentication = getAuthenticationTokenIfAvailable();
        if (authentication == null) {
            throw new InsufficientAuthenticationException("There is no ForceAuthenticationToken in the current security context");
        }
        return authentication;
    }

    /**
     * Gets the current Salesforce authentication information.
     *
     * @return the current authentication information or <code>null</code> in none exists
     */
    private static ForceAuthenticationToken getAuthenticationTokenIfAvailable() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication instanceof ForceAuthenticationToken) {
            return (ForceAuthenticationToken) authentication;
        } else {
            return null;
        }
    }
}
