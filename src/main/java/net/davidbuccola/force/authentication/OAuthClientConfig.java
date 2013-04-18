/*
 * Copyright, 2013, SALESFORCE.com
 * All Rights Reserved
 * Company Confidential
 */
package net.davidbuccola.force.authentication;

/**
 * Salesforce OAuth client configuration information.
 */
public interface OAuthClientConfig {
    /**
     * Gets the client identifier.
     * <p/>
     * This is also known as the consumer key in the Force Remote Access configuration.
     *
     * @return the client identifier
     */
    String getClientId();

    /**
     * Gets the client secret.
     * <p/>
     * This is also known as the consumer secret in the Force Remote Access configuration.
     *
     * @return the client secret
     */
    String getClientSecret();

    /**
     * Gets the URL of the OAuth server.
     *
     * @return the URL of the OAuth server
     */
    String getServerURL();

    /**
     * Gets the scope.
     * <p/>
     * The scope is a apace separated list of values that declare what kind of access is client intends.
     *
     * @return the client secret
     */
    String getScope();

    /**
     * Gets the login display type.
     *
     * @return the login display type.
     */
    String getDisplay();

    /**
     * Gets the special prompt settings.
     *
     * @return the prompt settings.
     */
    String getPrompt();
}
