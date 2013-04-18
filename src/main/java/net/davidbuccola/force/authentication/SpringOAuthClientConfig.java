/*
 * Copyright, 2012-2013, SALESFORCE.com
 * All Rights Reserved
 * Company Confidential
 */
package net.davidbuccola.force.authentication;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.apache.commons.lang.builder.ReflectionToStringBuilder;
import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.beans.factory.InitializingBean;

import java.io.Serializable;

/**
 * A bean for holding Salesforce OAuth client configuration information.
 * <p/>
 * This bean is designed to work with Spring so that you can configure using Spring dependency injection.
 */
public final class SpringOAuthClientConfig implements InitializingBean, Serializable, OAuthClientConfig {
    private static final long serialVersionUID = -7937127472782784213L;

    private String clientId;
    private String clientSecret;
    private String serverURL;
    private String scope;
    private String display;
    private String prompt;

    @Override
    public String getClientId() {
        return clientId;
    }

    @Override
    public String getClientSecret() {
        return clientSecret;
    }

    @Override
    public String getServerURL() {
        return serverURL;
    }

    @Override
    public String getScope() {
        return scope;
    }

    @Override
    public String getDisplay() {
        return display;
    }

    @Override
    public String getPrompt() {
        return prompt;
    }

    /**
     * Sets the client identifier.
     * <p/>
     * This is also known as the consumer key in the Force Remote Access configuration.
     *
     * @param clientId the client identifier
     */
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    /**
     * Sets the client secret.
     * <p/>
     * This is also known as the consumer secret in the Force Remote Access configuration.
     *
     * @param clientSecret the client secret
     */
    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    /**
     * Sets the URL of the OAuth server.
     *
     * @param serverURL the URL of the OAuth server
     */
    public void setServerURL(String serverURL) {
        this.serverURL = serverURL;
    }

    /**
     * Sets the scope.
     * <p/>
     * The scope is a apace separated list of values that declare what kind of access is client intends.
     *
     * @param scope the client scope
     */
    public void setScope(String scope) {
        this.scope = scope;
    }

    /**
     * Sets the login display type.
     *
     * @param display the login display type.
     */
    public void setDisplay(String display) {
        this.display = display;
    }

    /**
     * sets the special prompt settings.
     *
     * @param prompt the prompt settings.
     */
    public void setPrompt(String prompt) {
        this.prompt = prompt;
    }

    @Override
    public void afterPropertiesSet() {
        if (clientId == null) {
            throw new BeanInitializationException("clientId is not set");
        }
        if (clientSecret == null) {
            throw new BeanInitializationException("clientSecret is not set");
        }
        if (serverURL == null) {
            throw new BeanInitializationException("serverURL is not set");
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof OAuthClientConfig)) {
            return false;
        }
        SpringOAuthClientConfig that = (SpringOAuthClientConfig) o;
        return new EqualsBuilder()
            .append(this.clientId, that.clientId)
            .append(this.clientSecret, that.clientSecret)
            .append(this.serverURL, that.serverURL)
            .append(this.scope, that.scope)
            .append(this.display, that.display)
            .append(this.prompt, that.prompt)
            .isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(19, 37)
            .append(clientId)
            .append(clientSecret)
            .append(serverURL)
            .append(scope)
            .append(display)
            .append(prompt)
            .toHashCode();
    }

    @Override
    public String toString() {
        return ReflectionToStringBuilder.reflectionToString(this);
    }
}
