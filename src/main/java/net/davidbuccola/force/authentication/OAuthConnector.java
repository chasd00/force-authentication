/*
 * Copyright, 2012, SALESFORCE.com
 * All Rights Reserved
 * Company Confidential
 */
package net.davidbuccola.force.authentication;

/**
 * An abstraction of the communication and configuration aspects of the Salesforce OAuth interchange. This interface
 * isolates the I/O and configuration so that it can be mocked for testing.
 * <p/>
 * This class does not handle the entire exchange. It is just a helper that gets involved at key points in the
 * sequence.
 */
public interface OAuthConnector {
    /**
     * Builds the "authorize" URL that will kick off the OAuth sequence with Salesforce.
     *
     * @param callbackUri the OAuth callback URI that the Salesforce server will call back with the "code" for the next
     *                    phase of the exchange. This is the OAuth callback URI that is registered with the Salesforce
     *                    connected application configuration.
     * @param state       state information that will be returned with the callback
     * @return the "authorize" URL
     */
    String buildAuthorizeUri(String callbackUri, String state);

    /**
     * Obtain the OAuth access token from the Salesforce server.
     *
     * @param code        the "code" that was received in the OAuth callback from the earlier phase of the exchange.
     * @param callbackUri the OAuth callback URI that is registered with the Salesforce connected application
     *                    configuration. In this particular phase of the exchange the callback will not be invoked but
     *                    it is used by the server for verification.
     * @return the access token
     */
    ForceAuthenticationToken getToken(String code, String callbackUri);
}
