/*
 * Copyright, 2013, SALESFORCE.com
 * All Rights Reserved
 * Company Confidential
 */
package net.davidbuccola.force.authentication;

import org.springframework.security.core.AuthenticationException;

/**
 * Thrown to indicate a problem during the Salesforce OAuth exchange.
 */
public class OAuthException extends AuthenticationException {
    private static final long serialVersionUID = -4478385027052820020L;

    /**
     * Constructs a new instance with the specified detail message.
     *
     * @param message the detail message
     */
    public OAuthException(String message) {
        super(message);
    }

    /**
     * Constructs a new instance with the specified message and cause.
     *
     * @param message the detail message
     * @param cause   the cause. <tt>null</tt> is permitted, and indicates that the cause is nonexistent or unknown.
     */
    public OAuthException(String message, Throwable cause) {
        super(message, cause);
    }
}
