/*
 * Copyright, 2013, SALESFORCE.com
 * All Rights Reserved
 * Company Confidential
 */
package net.davidbuccola.force.authentication;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.apache.commons.lang.builder.ReflectionToStringBuilder;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * An Spring {@link org.springframework.security.core.Authentication} implementation that holds the salient results of a
 * Salesforce authentication.
 * <p/>
 * The authentication information can be obtained in a number of different ways. The information could have been the
 * result of a Salesforce OAuth exchange, a Salesforce Canvas request, or contained in HTTP headers on the request.
 * <p/>
 * This implementation represents a least common denominator of required information from the various sources of
 * authorization.
 */
public class ForceAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = -2803445171111658833L;

    private final String userId;
    private final String accessToken;
    private final String instanceUrl;

    public ForceAuthenticationToken(String userId, String accessToken, String instanceUrl, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.userId = userId;
        this.accessToken = accessToken;
        this.instanceUrl = instanceUrl;

        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return getAccessToken();
    }

    @Override
    public Object getPrincipal() {
        return getUserId();
    }

    /**
     * Gets the Salesforce user ID associated with the OAuth access token.
     *
     * @return user ID
     */
    public final String getUserId() {
        return userId;
    }

    /**
     * Gets the OAuth access token that can be used for outbound communications with Salesforce.
     *
     * @return OAuth access token.
     */
    public final String getAccessToken() {
        return accessToken;
    }

    /**
     * Gets the URL of the Salesforce instance that should be used for outbound communications with Salesforce.
     *
     * @return instance URL
     */
    public final String getInstanceUrl() {
        return instanceUrl;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ForceAuthenticationToken)) {
            return false;
        }
        ForceAuthenticationToken that = (ForceAuthenticationToken) o;
        return new EqualsBuilder()
            .append(this.userId, that.userId)
            .append(this.accessToken, that.accessToken)
            .append(this.instanceUrl, that.instanceUrl)
            .isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37)
            .append(userId)
            .append(accessToken)
            .append(instanceUrl)
            .toHashCode();
    }

    @Override
    public String toString() {
        return ReflectionToStringBuilder.reflectionToString(this);
    }
}
