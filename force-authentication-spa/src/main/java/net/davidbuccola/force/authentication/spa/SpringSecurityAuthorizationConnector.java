/*
 * Copyright, 2012-2013, SALESFORCE.com
 * All Rights Reserved
 * Company Confidential
 */
package net.davidbuccola.force.authentication.spa;

import java.net.URI;

import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import com.force.spa.AuthorizationConnector;

import net.davidbuccola.force.authentication.AuthenticationUtils;
import net.davidbuccola.force.authentication.ForceAuthenticationToken;

/**
 * An {@link AuthorizationConnector} implementation that knows how to obtain authorization and instance information from
 * the {@link ForceAuthenticationToken} stored in the current Spring security context.
 */
@Primary
@Component
public class SpringSecurityAuthorizationConnector implements AuthorizationConnector {

    @Override
    public String getAuthorization() {
        ForceAuthenticationToken authentication = AuthenticationUtils.getAuthenticationToken();
        return "Bearer " + authentication.getAccessToken();
    }

    @Override
    public URI getInstanceUrl() {
        ForceAuthenticationToken authentication = AuthenticationUtils.getAuthenticationToken();
        return URI.create(authentication.getInstanceUrl());
    }

    @Override
    public String getUserId() {
        ForceAuthenticationToken authentication = AuthenticationUtils.getAuthenticationToken();
        return authentication.getUserId();
    }
}
